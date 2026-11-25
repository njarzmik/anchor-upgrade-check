"""Anchor IDLs: decoding the on-chain IDL account, and listing what an IDL says the binary contains.

Two IDL formats exist. Anchor 0.30 and later write each instruction's, event's and account's
discriminator into the IDL. Older IDLs do not, so the discriminators are recomputed from names,
the same way Anchor does: sha256("global:<snake_case_name>"), sha256("event:<Name>") and
sha256("account:<Name>"), first 8 bytes.
"""

import hashlib
import json
import zlib
from dataclasses import dataclass
from typing import Any

# Anchor declares IdlAccount as #[account("internal")], so its discriminator hashes the namespace
# "internal", not the usual "account".
IDL_ACCOUNT_DISC = hashlib.sha256(b"internal:IdlAccount").digest()[:8]
_IDL_HEADER_LEN = 44  # 8 discriminator + 32 authority + 4 data length


class IdlError(ValueError):
    """The account is not an Anchor IDL account, or its payload does not decode."""


@dataclass(frozen=True)
class IdlAccount:
    authority: bytes
    compressed_len: int
    idl: dict[str, Any]


@dataclass(frozen=True)
class Item:
    kind: str  # "instruction", "event" or "account"
    name: str
    disc: bytes
    from_idl: bool  # False when recomputed from the name (older IDL format)


def sighash(namespace: str, name: str) -> bytes:
    return hashlib.sha256(f"{namespace}:{name}".encode()).digest()[:8]


def decode_idl_account(data: bytes) -> IdlAccount:
    """Account layout: discriminator, authority, u32 length, then zlib-compressed JSON."""
    if len(data) < _IDL_HEADER_LEN:
        raise IdlError(f"account is {len(data)} bytes, shorter than the {_IDL_HEADER_LEN}-byte header")
    if data[:8] != IDL_ACCOUNT_DISC:
        raise IdlError(f"discriminator {data[:8].hex()} is not IdlAccount's {IDL_ACCOUNT_DISC.hex()}")
    n = int.from_bytes(data[40:44], "little")
    if _IDL_HEADER_LEN + n > len(data):
        raise IdlError(f"declared length {n} runs past the account ({len(data)} bytes)")
    try:
        idl = json.loads(zlib.decompress(data[_IDL_HEADER_LEN:_IDL_HEADER_LEN + n]))
    except (zlib.error, ValueError) as e:
        raise IdlError(f"payload does not decompress to JSON: {type(e).__name__}") from None
    if not isinstance(idl, dict):
        raise IdlError("payload is JSON but not an object")
    return IdlAccount(authority=data[8:40], compressed_len=n, idl=idl)


def idl_name(idl: dict[str, Any]) -> str:
    meta = idl.get("metadata") or {}
    return str(meta.get("name") or idl.get("name") or "?")


def idl_version(idl: dict[str, Any]) -> str:
    meta = idl.get("metadata") or {}
    return str(meta.get("version") or idl.get("version") or "?")


def is_new_format(idl: dict[str, Any]) -> bool:
    """True when the IDL carries its own discriminators (Anchor 0.30+)."""
    ixs = idl.get("instructions") or []
    return bool(ixs) and all("discriminator" in ix for ix in ixs)


def snake_case(name: str) -> str:
    """camelCase to snake_case with the word boundaries of the `heck` crate Anchor uses.

    Older IDLs store instruction names in camelCase, but the discriminator hashes the Rust
    snake_case name. This recovers it for ordinary names; a name like `init_2` became `init2` in
    the IDL and cannot be recovered, which is one reason the newer format stores the bytes.
    """
    out: list[str] = []
    for i, c in enumerate(name):
        if c.isupper():
            prev = name[i - 1] if i else ""
            nxt = name[i + 1] if i + 1 < len(name) else ""
            if i and prev != "_" and (not prev.isupper() or nxt.islower()):
                out.append("_")
            out.append(c.lower())
        else:
            out.append(c)
    return "".join(out)


def pascal_case(name: str) -> str:
    """The name Anchor logs at dispatch: `buy_exact_in` and `buyExactIn` both give `BuyExactIn`."""
    return "".join(p[:1].upper() + p[1:] for p in name.split("_"))


def _disc(entry: dict[str, Any], namespace: str, name: str) -> tuple[bytes, bool]:
    if "discriminator" in entry:
        return bytes(entry["discriminator"]), True
    return sighash(namespace, name), False


def items(idl: dict[str, Any]) -> list[Item]:
    """Every instruction, event and account the IDL names, with its discriminator."""
    out = []
    for ix in idl.get("instructions") or []:
        disc, given = _disc(ix, "global", snake_case(ix["name"]))
        out.append(Item("instruction", ix["name"], disc, given))
    for ev in idl.get("events") or []:
        disc, given = _disc(ev, "event", ev["name"])
        out.append(Item("event", ev["name"], disc, given))
    for acc in idl.get("accounts") or []:
        disc, given = _disc(acc, "account", acc["name"])
        out.append(Item("account", acc["name"], disc, given))
    return out


def errors(idl: dict[str, Any]) -> list[tuple[int, str, str]]:
    """(code, name, message) for every custom error that has a message."""
    return [(int(e["code"]), e["name"], e["msg"]) for e in idl.get("errors") or [] if e.get("msg")]
