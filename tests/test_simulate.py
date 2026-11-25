import base64

import pytest

from anchor_upgrade_check.base58 import b58encode
from anchor_upgrade_check.simulate import (Expected, build_from_spec, matches, parse_expected,
                                           run_simulate)
from anchor_upgrade_check.tx import parse_tx
from synth import FakeRpc, addr, failing, key

FALLBACK = {"InstructionError": [0, {"Custom": 101}]}
ANCHOR_LOG = ("Program log: AnchorError occurred. Error Code: InstructionFallbackNotFound. "
              "Error Number: 101. Error Message: Fallback functions are not supported.")


def spec() -> dict:
    """Positive control: an 8-byte discriminator the toy program does not have."""
    return {"payer": addr("funded account"),
            "instructions": [{"program_id": addr("toy program"), "data_hex": "ffffffffffffffff",
                              "accounts": [{"pubkey": addr("vault"), "writable": True}]}]}


def sim_rpc(err) -> FakeRpc:
    return FakeRpc(handlers={"simulateTransaction": {
        "context": {"slot": 1}, "value": {"err": err, "logs": ["Program x invoke [1]", ANCHOR_LOG], "unitsConsumed": 4321}}})


def test_positive_control_passes_on_the_expected_code(capsys) -> None:
    raw = build_from_spec(spec())
    assert run_simulate(sim_rpc(FALLBACK), raw, parse_expected("101")) == 0
    out = capsys.readouterr().out
    assert "Custom 101 in instruction 0" in out and "AnchorError" in out and "PASS" in out


@pytest.mark.parametrize("expect,index", [("6000", None), ("ok", None), ("101", 1), ("InvalidAccountData", None)])
def test_wrong_outcome_fails(expect: str, index: int | None, capsys) -> None:
    raw = build_from_spec(spec())
    assert run_simulate(sim_rpc(FALLBACK), raw, parse_expected(expect, index)) == 1
    assert "FAIL" in capsys.readouterr().out


def test_clean_run_only_passes_when_ok_was_expected() -> None:
    raw = build_from_spec(spec())
    assert run_simulate(sim_rpc(None), raw, parse_expected("ok")) == 0
    assert run_simulate(sim_rpc(None), raw, parse_expected("101")) == 1


def test_signatures_are_zeroed_and_checks_are_off() -> None:
    raw = build_from_spec(spec())
    signed = raw[:1] + bytes([0x5A]) * 64 + raw[65:]  # as if someone passed a signed transaction
    rpc = sim_rpc(FALLBACK)
    run_simulate(rpc, signed, parse_expected("101"))
    (method, (tx_b64, cfg)), = rpc.calls
    sent = base64.b64decode(tx_b64)
    assert method == "simulateTransaction" and sent == raw
    assert parse_tx(sent).signatures == (bytes(64),)
    assert cfg["sigVerify"] is False and cfg["replaceRecentBlockhash"] is True


def test_rpc_failure_is_no_verdict() -> None:
    raw = build_from_spec(spec())
    assert run_simulate(FakeRpc(handlers={"simulateTransaction": failing}), raw, parse_expected("101")) == 3


def test_unparseable_transaction_is_refused_before_any_request() -> None:
    rpc = sim_rpc(FALLBACK)
    assert run_simulate(rpc, bytes([0x80]) + bytes(200), parse_expected("101")) == 3
    assert rpc.calls == []


@pytest.mark.parametrize("text,err,want", [
    ("101", {"InstructionError": [2, {"Custom": 101}]}, True),
    ("0x65", {"InstructionError": [2, {"Custom": 101}]}, True),
    ("InvalidAccountData", {"InstructionError": [0, "InvalidAccountData"]}, True),
    ("BorshIoError", {"InstructionError": [0, {"BorshIoError": "Unknown"}]}, True),
    ("AccountNotFound", "AccountNotFound", True),
    ("InsufficientFundsForRent", {"InsufficientFundsForRent": {"account_index": 0}}, True),
    ("ok", None, True),
    ("101", None, False),
    ("101", "AccountNotFound", False),
    ("AccountNotFound", {"InstructionError": [0, {"Custom": 101}]}, False),
])
def test_error_matching(text: str, err, want: bool) -> None:
    assert matches(parse_expected(text), err) is want


def test_spec_needs_a_payer_and_round_trips() -> None:
    s = spec()
    del s["payer"]
    with pytest.raises(ValueError):
        build_from_spec(s)
    p = parse_tx(build_from_spec(s, payer=b58encode(key("funded account"))))
    assert p.account_keys[0] == key("funded account")
    assert p.instructions[0][2] == bytes.fromhex("ffffffffffffffff")
    assert Expected(custom=101, index=0).describe() == "Custom 101 in instruction 0"
