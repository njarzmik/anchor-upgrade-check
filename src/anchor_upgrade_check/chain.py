"""On-chain reads: a program's loader state, its deployed binary, and its Anchor IDL account."""

import base64
from dataclasses import dataclass
from typing import Any

from .base58 import b58encode, decode_pubkey
from .idl import IdlAccount, decode_idl_account
from .keys import UPGRADEABLE_LOADER, anchor_idl_address
from .loader import (PROGRAMDATA_HEADER_LEN, LoaderError, parse_program_account,
                     parse_programdata_header, program_binary)
from .rpc import RpcClient


@dataclass(frozen=True)
class Account:
    data: bytes
    owner: str
    executable: bool
    read_slot: int | None


@dataclass(frozen=True)
class ProgramState:
    program_id: str
    programdata: str
    slot: int
    authority: str | None
    read_slot: int | None

    def to_json(self) -> dict[str, Any]:
        return {"programdata": self.programdata, "slot": self.slot, "authority": self.authority}


def get_account(rpc: RpcClient, address: str, length: int | None = None) -> Account | None:
    """getAccountInfo in base64; `length` reads only the first bytes (a dataSlice)."""
    cfg: dict[str, Any] = {"encoding": "base64", "commitment": "confirmed"}
    if length is not None:
        cfg["dataSlice"] = {"offset": 0, "length": length}
    res = rpc.call("getAccountInfo", [address, cfg]) or {}
    value = res.get("value")
    if not value:
        return None
    return Account(data=base64.b64decode(value["data"][0]), owner=value["owner"],
                   executable=bool(value.get("executable")),
                   read_slot=(res.get("context") or {}).get("slot"))


def _programdata_address(rpc: RpcClient, program_id: str) -> str:
    decode_pubkey(program_id)
    acc = get_account(rpc, program_id)
    if acc is None:
        raise LoaderError(f"no account at {program_id}")
    if acc.owner != UPGRADEABLE_LOADER:
        raise LoaderError(f"owned by {acc.owner}, not the upgradeable loader; nothing to watch")
    return b58encode(parse_program_account(acc.data))


def read_program(rpc: RpcClient, program_id: str) -> ProgramState:
    """Deploy slot and upgrade authority, from a 45-byte slice so a cron check stays cheap."""
    pd = _programdata_address(rpc, program_id)
    acc = get_account(rpc, pd, length=PROGRAMDATA_HEADER_LEN)
    if acc is None:
        raise LoaderError(f"programdata account {pd} does not exist")
    hdr = parse_programdata_header(acc.data)
    auth = b58encode(hdr.authority) if hdr.authority is not None else None
    return ProgramState(program_id, pd, hdr.slot, auth, acc.read_slot)


def read_binary(rpc: RpcClient, program_id: str) -> tuple[ProgramState, bytes, str]:
    """The whole programdata account: header state, the ELF, and how its end was found."""
    pd = _programdata_address(rpc, program_id)
    acc = get_account(rpc, pd)
    if acc is None:
        raise LoaderError(f"programdata account {pd} does not exist")
    hdr = parse_programdata_header(acc.data)
    elf, how = program_binary(acc.data)
    auth = b58encode(hdr.authority) if hdr.authority is not None else None
    return ProgramState(program_id, pd, hdr.slot, auth, acc.read_slot), elf, how


def read_idl(rpc: RpcClient, program_id: str) -> tuple[str, IdlAccount | None]:
    """The derived IDL address, and the decoded account (None when no IDL was published there).

    Anchor makes the IDL account owned by the program itself. An account at that address with any
    other owner is refused rather than trusted.
    """
    pid = decode_pubkey(program_id)
    address = b58encode(anchor_idl_address(pid))
    acc = get_account(rpc, address)
    if acc is None:
        return address, None
    if acc.owner != program_id:
        raise LoaderError(f"IDL account {address} is owned by {acc.owner}, not by the program")
    return address, decode_idl_account(acc.data)
