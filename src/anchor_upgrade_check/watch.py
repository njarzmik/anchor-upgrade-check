"""Detect a program redeploy by comparing its programdata header with a stored baseline.

The loader rewrites the deploy slot every time it redeploys a program, so a changed slot is the
cheapest reliable signal that the code you trade through is no longer the code you checked.
A change keeps failing on every run until it is accepted with --accept, which should happen only
after the new binary has been scanned and simulated.
"""

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .chain import ProgramState, read_program
from .loader import LoaderError
from .rpc import RpcClient, RpcError

OK, CHANGED, NO_VERDICT = 0, 1, 3


@dataclass(frozen=True)
class TxSummary:
    signature: str
    slot: int | None
    block_time: int | None
    err: Any
    signers: list[str]
    instructions: list[str]


def compare(stored: dict[str, Any] | None, now: ProgramState) -> tuple[str, list[str]]:
    """('baseline' | 'unchanged' | 'changed', list of differences)."""
    if stored is None:
        return "baseline", []
    diffs = [f"{key}: {stored.get(key)} -> {value}"
             for key, value in now.to_json().items() if stored.get(key) != value]
    return ("changed" if diffs else "unchanged"), diffs


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    state = json.loads(path.read_text())
    if not isinstance(state, dict):
        raise ValueError(f"{path} does not hold a JSON object")
    return state


def save_state(path: Path, state: dict[str, Any]) -> None:
    """Write through a temporary file, so a crash mid-write cannot leave a half baseline."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def summarize_tx(signature: str, tx: dict[str, Any]) -> TxSummary:
    """Signers and top-level instructions of a jsonParsed getTransaction result."""
    msg = (tx.get("transaction") or {}).get("message") or {}
    signers = [k["pubkey"] for k in msg.get("accountKeys") or [] if isinstance(k, dict) and k.get("signer")]
    ixs = []
    for ix in msg.get("instructions") or []:
        prog = ix.get("program") or ix.get("programId") or "?"
        parsed = ix.get("parsed")
        kind = parsed.get("type") if isinstance(parsed, dict) else None
        ixs.append(f"{prog}:{kind}" if kind else str(prog))
    return TxSummary(signature, tx.get("slot"), tx.get("blockTime"), (tx.get("meta") or {}).get("err"),
                     signers, ixs)


def find_deploy_txs(rpc: RpcClient, programdata: str, slot: int, limit: int) -> list[TxSummary | str]:
    """Transactions at the deploy slot among the programdata account's newest `limit` signatures.

    A redeploy writes the programdata account, so the transaction that did it is in that
    account's signature list at exactly the deploy slot. A transaction that cannot be fetched is
    returned as a message string instead of being dropped.
    """
    sigs = rpc.call("getSignaturesForAddress", [programdata, {"limit": limit, "commitment": "confirmed"}]) or []
    out: list[TxSummary | str] = []
    for s in sigs:
        if s.get("slot") != slot:
            continue
        try:
            tx = rpc.call("getTransaction", [s["signature"], {"encoding": "jsonParsed", "commitment": "confirmed",
                                                              "maxSupportedTransactionVersion": 0}])
        except RpcError as e:
            out.append(f"{s['signature']}: not fetched ({e})")
            continue
        out.append(summarize_tx(s["signature"], tx) if tx else f"{s['signature']}: not found")
    return out


def _utc(ts: int | None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else "block time unknown"


def _block_time(rpc: RpcClient, slot: int) -> int | None:
    try:
        return rpc.call("getBlockTime", [slot])
    except RpcError:
        return None  # informational only; the verdict never depends on it


def _print_state(now: ProgramState, when: int | None, status: str, diffs: list[str]) -> None:
    print(f"program      {now.program_id}")
    print(f"programdata  {now.programdata}")
    print(f"deploy slot  {now.slot:,} ({_utc(when)})")
    print(f"authority    {now.authority or 'none: the program can no longer be upgraded'}")
    print(f"read at slot {now.read_slot:,}" if now.read_slot else "read at slot unknown")
    print(f"state        {status.upper()}" + "".join(f"\n             {d}" for d in diffs))


def _print_txs(txs: list[TxSummary | str], slot: int, limit: int) -> None:
    if not txs:
        print(f"deploy tx    none at slot {slot:,} among the newest {limit} signatures")
    for t in txs:
        if isinstance(t, str):
            print(f"deploy tx    {t}")
            continue
        print(f"deploy tx    {t.signature} ({_utc(t.block_time)}) err {t.err}")
        print(f"             signers {t.signers}")
        print(f"             instructions {t.instructions}")


def watch_one(rpc: RpcClient, program_id: str, state: dict[str, Any], accept: bool, limit: int) -> int:
    """Check one program, update `state` in place when allowed, return its exit code."""
    try:
        now = read_program(rpc, program_id)
    except (RpcError, LoaderError, ValueError) as e:
        print(f"program      {program_id}\nstate        NO VERDICT: {e}")
        return NO_VERDICT
    status, diffs = compare(state.get(program_id), now)
    _print_state(now, _block_time(rpc, now.slot), status, diffs)
    if status != "unchanged" and limit > 0:
        try:
            _print_txs(find_deploy_txs(rpc, now.programdata, now.slot, limit), now.slot, limit)
        except RpcError as e:
            print(f"deploy tx    lookup failed ({e})")
    if status == "baseline" or (status == "changed" and accept):
        state[program_id] = now.to_json()
        print("             recorded as the new baseline")
        return OK
    return CHANGED if status == "changed" else OK


def run_watch(rpc: RpcClient, program_ids: list[str], state_path: Path, accept: bool, limit: int) -> int:
    """Exit 1 if any program changed (the result to act on), else 3 if any could not be read, else 0."""
    try:
        state = load_state(state_path)
    except (OSError, ValueError) as e:
        print(f"state file {state_path}: NO VERDICT: {e}")
        return NO_VERDICT
    before = json.dumps(state, sort_keys=True)
    codes = []
    for i, pid in enumerate(program_ids):
        if i:
            print()
        codes.append(watch_one(rpc, pid, state, accept, limit))
    if json.dumps(state, sort_keys=True) != before:
        save_state(state_path, state)
    if CHANGED in codes:
        return CHANGED
    return NO_VERDICT if NO_VERDICT in codes else OK
