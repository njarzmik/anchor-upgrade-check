"""Synthetic inputs for the offline tests: a toy Anchor IDL, a hand-built sBPF ELF with planted
discriminators and strings, upgradeable-loader accounts, and a scripted RPC.

Nothing here comes from a real program. Every key is sha256 of a label.
"""

import base64
import hashlib
import struct
from typing import Any, Callable

from anchor_upgrade_check.base58 import b58encode
from anchor_upgrade_check.idl import pascal_case, sighash
from anchor_upgrade_check.keys import UPGRADEABLE_LOADER
from anchor_upgrade_check.rpc import RpcError


def key(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def addr(label: str) -> str:
    return b58encode(key(label))


# ---- a toy Anchor program ---------------------------------------------------------------

INSTRUCTIONS = ["initialize", "deposit", "withdraw", "set_authority"]
LEGACY_NAMES = {"initialize": "initialize", "deposit": "deposit", "withdraw": "withdraw",
                "set_authority": "setAuthority"}
EVENTS = ["Deposited"]
ACCOUNTS = ["Vault"]
ERRORS = [(6000, "AmountTooSmall", "Amount is below the minimum"),
          (6001, "VaultLocked", "Vault is locked"),
          (6002, "Unauthorized", "Signer is not the vault authority")]

DISC = {**{n: sighash("global", n) for n in INSTRUCTIONS},
        **{n: sighash("event", n) for n in EVENTS},
        **{n: sighash("account", n) for n in ACCOUNTS}}

# Which planted discriminators the compiler "loaded with lddw"; the rest sit in .rodata.
LDDW_DEFAULT = ("initialize", "set_authority", "Deposited")


def toy_idl(new_format: bool = True) -> dict[str, Any]:
    """The same program in the Anchor 0.30+ format (discriminators given) or the older one."""
    errors = [{"code": c, "name": n, "msg": m} for c, n, m in ERRORS]
    if new_format:
        return {
            "address": addr("toy program"),
            "metadata": {"name": "toy_vault", "version": "0.1.0", "spec": "0.1.0"},
            "instructions": [{"name": n, "discriminator": list(DISC[n]), "accounts": [], "args": []}
                             for n in INSTRUCTIONS],
            "accounts": [{"name": n, "discriminator": list(DISC[n])} for n in ACCOUNTS],
            "events": [{"name": n, "discriminator": list(DISC[n])} for n in EVENTS],
            "errors": errors,
        }
    return {
        "version": "0.1.0", "name": "toy_vault",
        "instructions": [{"name": LEGACY_NAMES[n], "accounts": [], "args": []} for n in INSTRUCTIONS],
        "accounts": [{"name": n, "type": {"kind": "struct", "fields": []}} for n in ACCOUNTS],
        "events": [{"name": n, "fields": []} for n in EVENTS],
        "errors": errors,
    }


# ---- sBPF and ELF -----------------------------------------------------------------------

def ins(op: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    return struct.pack("<BBhi", op, (src << 4) | dst, off, imm)


def lddw(dst: int, value: bytes) -> bytes:
    """`lddw dst, imm64` loading the 8 bytes of `value` as a little-endian constant."""
    imm = int.from_bytes(value, "little")
    return struct.pack("<BBhI", 0x18, dst, 0, imm & 0xFFFFFFFF) + struct.pack("<BBhI", 0, 0, 0, imm >> 32)


EXIT = ins(0x95)
MOV0 = ins(0xB7, dst=0, imm=0)


def build_elf(text: bytes, rodata: bytes, machine: int = 247) -> bytes:
    """A minimal ELF64: header, .text, .rodata, .shstrtab, then the section header table.

    The table comes last, as in linker output, so the file ends with the zero high bytes of the
    last header's fields: an ELF that legitimately ends in zeros.
    """
    shstrtab = b"\0.text\0.rodata\0.shstrtab\0"
    off_text = 64
    off_ro = off_text + len(text)
    off_str = off_ro + len(rodata)
    shoff = (off_str + len(shstrtab) + 7) // 8 * 8
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, off_text, 0, shoff, 0, 64, 56, 0, 64, 4, 3)

    def sh(name: int, typ: int, flags: int, off: int, size: int, align: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, off, off, size, 0, 0, align, 0)

    table = (bytes(64) + sh(1, 1, 0x6, off_text, len(text), 8) + sh(7, 1, 0x2, off_ro, len(rodata), 1)
             + sh(15, 3, 0, off_str, len(shstrtab), 1))
    body = header + text + rodata + shstrtab
    return body + bytes(shoff - len(body)) + table


def toy_binary(*, omit: tuple[str, ...] = (), lddw_items: tuple[str, ...] = LDDW_DEFAULT,
               log_names: list[str] | None = None, error_msgs: list[str] | None = None,
               text_extra: bytes = b"", rodata_extra: bytes = b"") -> bytes:
    """The toy program as a compiler might lay it out. `omit` drops discriminators entirely."""
    text = MOV0
    for name in lddw_items:
        if name not in omit:
            text += lddw(1, DISC[name]) + ins(0x1D, dst=2, src=1, off=1)  # lddw r1; jeq r2, r1
    text += text_extra + EXIT
    rodata = b"".join(DISC[n] for n in DISC if n not in lddw_items and n not in omit)
    names = log_names if log_names is not None else [pascal_case(n) for n in INSTRUCTIONS]
    rodata += b"".join(b"Instruction: " + n.encode() for n in names)  # packed, no separators
    rodata += b"Program log: other literal"
    msgs = error_msgs if error_msgs is not None else [m for _, _, m in ERRORS]
    rodata += b"".join(m.encode() for m in msgs) + b"\x00\x01" + rodata_extra
    return build_elf(text, rodata)


# ---- upgradeable loader accounts ---------------------------------------------------------

def programdata_bytes(slot: int, authority: bytes | None, elf: bytes = b"", pad: int = 0) -> bytes:
    option = b"\x01" + authority if authority is not None else b"\x00" + bytes(32)
    return (3).to_bytes(4, "little") + slot.to_bytes(8, "little") + option + elf + bytes(pad)


def program_accounts(label: str, slot: int, authority: bytes | None, elf: bytes = b"", pad: int = 0) -> dict:
    """Program account -> programdata account, keyed by base58 address, as FakeRpc serves them."""
    pd = key(label + " programdata")
    return {
        addr(label): {"data": (2).to_bytes(4, "little") + pd, "owner": UPGRADEABLE_LOADER, "executable": True},
        b58encode(pd): {"data": programdata_bytes(slot, authority, elf, pad), "owner": UPGRADEABLE_LOADER},
    }


# ---- a scripted RPC ----------------------------------------------------------------------

class FakeRpc:
    """Serves getAccountInfo from a dict (honouring dataSlice) and other methods from handlers."""

    def __init__(self, accounts: dict | None = None,
                 handlers: dict[str, Callable[[list], Any] | Any] | None = None) -> None:
        self.accounts = accounts or {}
        self.handlers = handlers or {}
        self.calls: list[tuple[str, list]] = []

    def methods(self) -> list[str]:
        return [m for m, _ in self.calls]

    def call(self, method: str, params: list) -> Any:
        self.calls.append((method, params))
        if method in self.handlers:
            h = self.handlers[method]
            return h(params) if callable(h) else h
        if method == "getAccountInfo":
            address, cfg = params
            acc = self.accounts.get(address)
            if acc is None:
                return {"context": {"slot": 1000}, "value": None}
            data = acc["data"]
            if "dataSlice" in cfg:
                s = cfg["dataSlice"]
                data = data[s["offset"]:s["offset"] + s["length"]]
            return {"context": {"slot": 1000},
                    "value": {"data": [base64.b64encode(data).decode(), "base64"], "owner": acc["owner"],
                              "executable": acc.get("executable", False), "lamports": 1}}
        raise RpcError(f"{method}: not scripted")


def failing(params: list) -> Any:
    raise RpcError("scripted failure")
