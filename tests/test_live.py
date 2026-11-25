"""Opt-in checks against a real RPC. Skipped unless AUC_LIVE_PROGRAM names an upgradeable program
(and SOLANA_RPC_URL, if set, picks the endpoint). They only read; nothing is sent."""

import os

import pytest

from anchor_upgrade_check.chain import read_binary, read_idl, read_program
from anchor_upgrade_check.rpc import Rpc

PROGRAM = os.environ.get("AUC_LIVE_PROGRAM")
pytestmark = pytest.mark.skipif(not PROGRAM, reason="set AUC_LIVE_PROGRAM to run live checks")


def test_live_header_binary_and_idl() -> None:
    rpc = Rpc()
    state = read_program(rpc, PROGRAM)
    assert state.slot > 0
    full, elf, how = read_binary(rpc, PROGRAM)
    assert full.slot >= state.slot and elf[:4] == b"\x7fELF" and how == "elf headers"
    address, acc = read_idl(rpc, PROGRAM)
    assert address and (acc is None or isinstance(acc.idl, dict))
