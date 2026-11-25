"""Command line: watch, dump, fetch-idl, scan, simulate.

Exit codes, shared by every command: 0 pass, 1 the check failed (a change, a mismatch, the wrong
error), 2 usage, 3 no verdict (the chain could not be read or the input could not be parsed).
A command that cannot see enough to answer says so with 3; it never falls back to 0.
"""

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from . import scan as scanmod
from .base58 import b58encode
from .chain import read_binary, read_idl
from .idl import IdlError, idl_name, idl_version
from .loader import LoaderError
from .rpc import URL_ENV, Rpc, RpcError
from .simulate import build_from_spec, parse_expected, run_simulate
from .tx import TxError
from .watch import run_watch

NO_VERDICT = 3


def _cmd_watch(a: argparse.Namespace) -> int:
    return run_watch(Rpc(a.rpc), a.program_id, Path(a.state), a.accept, a.sigs)


def _cmd_dump(a: argparse.Namespace) -> int:
    try:
        st, elf, how = read_binary(Rpc(a.rpc), a.program_id)
    except (RpcError, LoaderError, ValueError) as e:
        print(f"NO VERDICT: {e}")
        return NO_VERDICT
    Path(a.out).write_bytes(elf)
    print(f"deploy slot  {st.slot:,}\nauthority    {st.authority or 'none'}")
    print(f"binary       {len(elf):,} bytes (end found from {how})\nsha256       {hashlib.sha256(elf).hexdigest()}")
    print(f"written to   {a.out}")
    return 0


def _cmd_fetch_idl(a: argparse.Namespace) -> int:
    try:
        address, acc = read_idl(Rpc(a.rpc), a.program_id)
    except (RpcError, LoaderError, IdlError, ValueError) as e:
        print(f"NO VERDICT: {e}")
        return NO_VERDICT
    print(f"idl account  {address}")
    if acc is None:
        print("no Anchor IDL account at that address (never published, or closed)")
        return 1
    idl = acc.idl
    print(f"authority    {b58encode(acc.authority)}\ncompressed   {acc.compressed_len:,} bytes")
    print(f"idl          {idl_name(idl)} {idl_version(idl)}: {len(idl.get('instructions') or [])} instructions, "
          f"{len(idl.get('events') or [])} events, {len(idl.get('errors') or [])} errors")
    if idl.get("address") not in (None, a.program_id):
        print(f"WARNING      the IDL's own address field is {idl['address']}, not the program id")
    Path(a.out).write_text(json.dumps(idl, indent=2) + "\n")
    print(f"written to   {a.out}")
    return 0


def _cmd_scan(a: argparse.Namespace) -> int:
    try:
        blob = Path(a.binary).read_bytes()
        idl = json.loads(Path(a.idl).read_text())
        report = scanmod.scan(blob, idl, context=a.context)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"NO VERDICT: cannot read the inputs: {type(e).__name__}: {e}")
        return NO_VERDICT
    print(scanmod.render(report))
    return 1 if report.failures() else 0


def _read_tx(a: argparse.Namespace) -> bytes:
    if a.ix:
        return build_from_spec(json.loads(Path(a.ix).read_text()), a.payer)
    text = sys.stdin.read() if a.tx == "-" else Path(a.tx).read_text()
    return base64.b64decode(text.strip(), validate=True)


def _cmd_simulate(a: argparse.Namespace) -> int:
    if bool(a.tx) == bool(a.ix):
        print("give exactly one of TX (a file with a base64 transaction, or -) and --ix SPEC.json")
        return 2
    try:
        raw = _read_tx(a)
        expected = parse_expected(a.expect_error, a.expect_index)
    except (OSError, ValueError, KeyError, TxError) as e:
        print(f"NO VERDICT: cannot build or read the transaction: {type(e).__name__}: {e}")
        return NO_VERDICT
    return run_simulate(Rpc(a.rpc), raw, expected, a.logs)


def build_parser() -> argparse.ArgumentParser:
    rpc = argparse.ArgumentParser(add_help=False)
    rpc.add_argument("--rpc", help=f"RPC URL (default: ${URL_ENV}, else the public mainnet endpoint)")
    p = argparse.ArgumentParser(prog="anchor-upgrade-check",
                                description="Detect a Solana program upgrade and check the new binary against its Anchor IDL.")
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("watch", parents=[rpc], help="compare deploy slot and upgrade authority with a stored baseline")
    w.add_argument("program_id", nargs="+")
    w.add_argument("--state", default="upgrade_state.json", help="baseline file (default: %(default)s)")
    w.add_argument("--accept", action="store_true", help="record a detected change as the new baseline")
    w.add_argument("--sigs", type=int, default=25, help="signatures searched for the deploy tx; 0 skips (default: %(default)s)")
    w.set_defaults(fn=_cmd_watch)

    d = sub.add_parser("dump", parents=[rpc], help="save the deployed ELF without its account padding")
    d.add_argument("program_id")
    d.add_argument("-o", "--out", required=True)
    d.set_defaults(fn=_cmd_dump)

    f = sub.add_parser("fetch-idl", parents=[rpc], help="derive, read and decompress the on-chain Anchor IDL")
    f.add_argument("program_id")
    f.add_argument("-o", "--out", required=True)
    f.set_defaults(fn=_cmd_fetch_idl)

    s = sub.add_parser("scan", help="check a binary against an IDL, in both directions (offline)")
    s.add_argument("binary")
    s.add_argument("idl")
    s.add_argument("--context", type=int, default=300, help="bytes shown after the last known error message")
    s.set_defaults(fn=_cmd_scan)

    m = sub.add_parser("simulate", parents=[rpc], help="simulate unsigned and require an expected outcome")
    m.add_argument("tx", nargs="?", help="file holding a base64 transaction, or - for stdin")
    m.add_argument("--ix", help="JSON instruction spec to build an unsigned legacy transaction from")
    m.add_argument("--payer", help="fee payer address for --ix (an existing account with SOL; never signs)")
    m.add_argument("--expect-error", required=True, help="custom code (101, 0x65), error name, or ok")
    m.add_argument("--expect-index", type=int, help="instruction index the error must come from")
    m.add_argument("--logs", type=int, default=10, help="log lines to print (default: %(default)s)")
    m.set_defaults(fn=_cmd_simulate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
