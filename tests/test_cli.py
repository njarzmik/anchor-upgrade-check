import json
import zlib
from pathlib import Path

import pytest

from anchor_upgrade_check import cli
from anchor_upgrade_check.base58 import b58encode
from anchor_upgrade_check.idl import IDL_ACCOUNT_DISC
from anchor_upgrade_check.keys import anchor_idl_address
from synth import FakeRpc, addr, key, program_accounts, toy_binary, toy_idl


def write_inputs(tmp_path: Path, blob: bytes) -> tuple[str, str]:
    so, idl = tmp_path / "program.so", tmp_path / "idl.json"
    so.write_bytes(blob)
    idl.write_text(json.dumps(toy_idl()))
    return str(so), str(idl)


def test_scan_exit_codes(tmp_path: Path, capsys) -> None:
    assert cli.main(["scan", *write_inputs(tmp_path, toy_binary())]) == 0
    assert cli.main(["scan", *write_inputs(tmp_path, toy_binary(omit=("withdraw",)))]) == 1
    assert "withdraw" in capsys.readouterr().out
    assert cli.main(["scan", str(tmp_path / "absent.so"), str(tmp_path / "idl.json")]) == 3


def test_simulate_needs_exactly_one_input(capsys) -> None:
    assert cli.main(["simulate", "--expect-error", "101"]) == 2


def test_help_runs() -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["--help"])
    assert e.value.code == 0


@pytest.fixture
def fake_chain(monkeypatch):
    """Point the CLI's Rpc at a FakeRpc holding the toy program, its binary and its IDL."""
    elf = toy_binary()
    accounts = program_accounts("toy program", 777, key("upgrade authority"), elf, pad=2048)
    blob = zlib.compress(json.dumps(toy_idl()).encode())
    accounts[b58encode(anchor_idl_address(key("toy program")))] = {
        "data": IDL_ACCOUNT_DISC + key("idl authority") + len(blob).to_bytes(4, "little") + blob + bytes(100),
        "owner": addr("toy program")}
    rpc = FakeRpc(accounts)
    monkeypatch.setattr(cli, "Rpc", lambda url=None: rpc)
    return elf


def test_dump_then_fetch_idl_then_scan(tmp_path: Path, fake_chain: bytes) -> None:
    so, idl = tmp_path / "program.so", tmp_path / "idl.json"
    assert cli.main(["dump", addr("toy program"), "-o", str(so)]) == 0
    assert so.read_bytes() == fake_chain  # padding removed, nothing cut
    assert cli.main(["fetch-idl", addr("toy program"), "-o", str(idl)]) == 0
    assert json.loads(idl.read_text()) == toy_idl()
    assert cli.main(["scan", str(so), str(idl)]) == 0


def test_fetch_idl_refuses_an_account_the_program_does_not_own(tmp_path: Path, fake_chain, monkeypatch) -> None:
    rpc = cli.Rpc()
    rpc.accounts[b58encode(anchor_idl_address(key("toy program")))]["owner"] = addr("impostor")
    assert cli.main(["fetch-idl", addr("toy program"), "-o", str(tmp_path / "idl.json")]) == 3
    assert not (tmp_path / "idl.json").exists()


def test_fetch_idl_without_an_idl_account(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cli, "Rpc", lambda url=None: FakeRpc({}))
    assert cli.main(["fetch-idl", addr("toy program"), "-o", str(tmp_path / "idl.json")]) == 1
