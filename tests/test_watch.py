import json
from pathlib import Path

from anchor_upgrade_check.base58 import b58encode
from anchor_upgrade_check.watch import run_watch
from synth import FakeRpc, addr, failing, key, program_accounts

PID = addr("toy program")
PD = b58encode(key("toy program programdata"))


def deploy_tx(slot: int) -> dict:
    return {"slot": slot, "blockTime": 1_700_000_000, "meta": {"err": None},
            "transaction": {"message": {
                "accountKeys": [{"pubkey": addr("upgrade authority"), "signer": True, "writable": True},
                                {"pubkey": PD, "signer": False, "writable": True}],
                "instructions": [{"program": "bpf-upgradeable-loader", "programId": "loader",
                                  "parsed": {"type": "upgrade", "info": {}}}]}}}


def rpc_at(slot: int, authority: str = "upgrade authority", sigs: list | None = None) -> FakeRpc:
    return FakeRpc(program_accounts("toy program", slot, key(authority)), handlers={
        "getBlockTime": 1_700_000_000,
        "getSignaturesForAddress": sigs if sigs is not None else [],
        "getTransaction": lambda p: deploy_tx(int(p[0].split("-")[1])),
    })


def test_first_run_records_a_baseline(tmp_path: Path, capsys) -> None:
    state = tmp_path / "state.json"
    assert run_watch(rpc_at(500), [PID], state, accept=False, limit=25) == 0
    assert json.loads(state.read_text())[PID]["slot"] == 500
    assert "BASELINE" in capsys.readouterr().out


def test_unchanged_is_zero_and_skips_the_tx_lookup(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    run_watch(rpc_at(500), [PID], state, False, 25)
    rpc = rpc_at(500)
    assert run_watch(rpc, [PID], state, False, 25) == 0
    assert "getSignaturesForAddress" not in rpc.methods()


def test_new_deploy_slot_fails_until_accepted(tmp_path: Path, capsys) -> None:
    state = tmp_path / "state.json"
    run_watch(rpc_at(500), [PID], state, False, 25)
    sigs = [{"signature": "sig-900", "slot": 900}, {"signature": "sig-899", "slot": 899}]
    rpc = rpc_at(900, sigs=sigs)
    assert run_watch(rpc, [PID], state, False, 25) == 1
    out = capsys.readouterr().out
    assert "CHANGED" in out and "slot: 500 -> 900" in out
    assert "bpf-upgradeable-loader:upgrade" in out and addr("upgrade authority") in out
    assert [p[0] for m, p in rpc.calls if m == "getTransaction"] == ["sig-900"]  # only the deploy slot
    assert run_watch(rpc_at(900), [PID], state, False, 25) == 1  # still failing: nobody accepted it
    assert run_watch(rpc_at(900), [PID], state, True, 25) == 0
    assert run_watch(rpc_at(900), [PID], state, False, 25) == 0


def test_authority_change_alone_is_a_change(tmp_path: Path, capsys) -> None:
    state = tmp_path / "state.json"
    run_watch(rpc_at(500), [PID], state, False, 0)
    assert run_watch(rpc_at(500, authority="someone else"), [PID], state, False, 0) == 1
    assert "authority:" in capsys.readouterr().out


def test_unreadable_chain_is_no_verdict_and_keeps_the_baseline(tmp_path: Path, capsys) -> None:
    state = tmp_path / "state.json"
    run_watch(rpc_at(500), [PID], state, False, 25)
    before = state.read_text()
    assert run_watch(FakeRpc(handlers={"getAccountInfo": failing}), [PID], state, False, 25) == 3
    assert state.read_text() == before
    assert "NO VERDICT" in capsys.readouterr().out


def test_not_an_upgradeable_program_is_no_verdict(tmp_path: Path) -> None:
    accounts = program_accounts("toy program", 500, None)
    accounts[PID]["owner"] = addr("some other loader")
    assert run_watch(FakeRpc(accounts), [PID], tmp_path / "s.json", False, 0) == 3


def test_a_change_outranks_an_unreadable_program(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    run_watch(rpc_at(500), [PID], state, False, 0)
    assert run_watch(rpc_at(900), [PID, addr("missing program")], state, False, 0) == 1


def test_corrupt_state_file_is_no_verdict(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    state.write_text("[1, 2")
    assert run_watch(rpc_at(500), [PID], state, False, 0) == 3
