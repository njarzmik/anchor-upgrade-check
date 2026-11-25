"""simulateTransaction as a gate with an expected outcome.

A simulation that returns 'no error' proves little if the harness could not have returned
anything else. So each run states the error it expects, and the first runs against a new binary
should be positive controls: transactions built to fail with a known code (for an Anchor program
without a fallback function, an unknown 8-byte instruction discriminator must fail with framework
error 101, InstructionFallbackNotFound). Only once those fail as predicted is a clean result worth
reading.
"""

import base64
import json
from dataclasses import dataclass
from typing import Any

from .base58 import decode_pubkey
from .rpc import RpcClient, RpcError
from .tx import AccountMeta, Instruction, ParsedTx, build_legacy_tx, zero_signatures

PASS, FAIL, NO_VERDICT = 0, 1, 3


@dataclass(frozen=True)
class Expected:
    ok: bool = False
    custom: int | None = None
    name: str | None = None
    index: int | None = None

    def describe(self) -> str:
        what = "no error" if self.ok else (f"Custom {self.custom}" if self.custom is not None else str(self.name))
        return what + (f" in instruction {self.index}" if self.index is not None else "")


def parse_expected(text: str, index: int | None = None) -> Expected:
    """'ok' / 'none' for success, an integer for a custom program error, otherwise an error name."""
    t = text.strip()
    if t.lower() in ("ok", "none"):
        return Expected(ok=True, index=index)
    if t.isdigit():
        return Expected(custom=int(t), index=index)
    if t.lower().startswith("0x"):
        return Expected(custom=int(t, 16), index=index)
    return Expected(name=t, index=index)


def split_error(err: Any) -> tuple[int | None, Any]:
    """(instruction index or None, inner error) from a TransactionError in JSON form."""
    if isinstance(err, dict) and "InstructionError" in err:
        idx, inner = err["InstructionError"]
        return idx, inner
    return None, err


def describe_error(err: Any) -> str:
    if err is None:
        return "no error"
    idx, inner = split_error(err)
    if isinstance(inner, dict) and "Custom" in inner:
        text = f"Custom {inner['Custom']}"
    else:
        text = inner if isinstance(inner, str) else json.dumps(inner)
    return text + (f" in instruction {idx}" if idx is not None else "")


def matches(expected: Expected, err: Any) -> bool:
    if expected.ok:
        return err is None
    if err is None:
        return False
    idx, inner = split_error(err)
    if expected.index is not None and idx != expected.index:
        return False
    if expected.custom is not None:
        return isinstance(inner, dict) and inner.get("Custom") == expected.custom
    if isinstance(inner, str):
        return inner == expected.name
    return isinstance(inner, dict) and expected.name in inner


def build_from_spec(spec: dict[str, Any], payer: str | None = None) -> bytes:
    """An unsigned legacy transaction from a JSON instruction spec (see the README).

    The payer must be an existing system account with enough SOL for the fee, because the
    simulation still charges it. Nothing is signed, so it does not have to be a key you hold.
    """
    payer_text = payer or spec.get("payer")
    if not payer_text:
        raise ValueError("a fee payer is required (--payer or \"payer\" in the spec)")
    ixs = []
    for ix in spec["instructions"]:
        metas = tuple(AccountMeta(decode_pubkey(a["pubkey"]), bool(a.get("signer")), bool(a.get("writable")))
                      for a in ix.get("accounts") or [])
        ixs.append(Instruction(decode_pubkey(ix["program_id"]), metas, bytes.fromhex(ix.get("data_hex", ""))))
    return build_legacy_tx(decode_pubkey(payer_text), ixs)


def simulate(rpc: RpcClient, raw: bytes) -> tuple[ParsedTx, dict[str, Any]]:
    """Blank every signature, then simulate with signature checks off and a fresh blockhash."""
    blank, parsed = zero_signatures(raw)
    cfg = {"encoding": "base64", "sigVerify": False, "replaceRecentBlockhash": True, "commitment": "processed"}
    res = rpc.call("simulateTransaction", [base64.b64encode(blank).decode(), cfg]) or {}
    value = res.get("value")
    if not isinstance(value, dict):
        raise RpcError("simulateTransaction: reply has no value")
    return parsed, value


def anchor_lines(logs: list[str]) -> list[str]:
    return [line for line in logs if "AnchorError" in line or "Error Code:" in line]


def run_simulate(rpc: RpcClient, raw: bytes, expected: Expected, show_logs: int = 10) -> int:
    """Print the outcome and return 0 when it matches `expected`, 1 when not, 3 when unknown."""
    try:
        parsed, value = simulate(rpc, raw)
    except (RpcError, ValueError) as e:
        print(f"NO VERDICT: {e}")
        return NO_VERDICT
    err, logs = value.get("err"), value.get("logs") or []
    print(f"transaction  {parsed.version}, {len(parsed.signatures)} signature(s) sent as zeros, {len(raw)} bytes")
    print(f"result       {describe_error(err)}")
    for line in anchor_lines(logs):
        print(f"anchor       {line}")
    units = value.get("unitsConsumed")
    print(f"units        {units:,}" if isinstance(units, int) else "units        unknown")
    if show_logs and logs:
        print(f"logs (last {min(show_logs, len(logs))} of {len(logs)})")
        for line in logs[-show_logs:]:
            print(f"  {line}")
    ok = matches(expected, err)
    print(f"expected     {expected.describe()}\n{'PASS' if ok else 'FAIL'}")
    return PASS if ok else FAIL
