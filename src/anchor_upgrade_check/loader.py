"""Account layouts of the BPF upgradeable loader (bincode, little-endian).

An upgradeable program is two accounts. The program account holds only a pointer to its
programdata account. The programdata account holds a 45-byte header (the slot of the last deploy
and the upgrade authority) followed by the ELF and any zero padding left from allocation.
"""

from dataclasses import dataclass

from .elf import ElfError, parse_elf

TAG_PROGRAM = 2
TAG_PROGRAMDATA = 3
PROGRAMDATA_HEADER_LEN = 45  # u32 tag + u64 slot + Option<Pubkey> (1 + 32), fixed even when None


class LoaderError(ValueError):
    """The account data is not the loader state it should be."""


@dataclass(frozen=True)
class ProgramDataHeader:
    slot: int
    authority: bytes | None  # None: the program can no longer be upgraded


def _tag(data: bytes) -> int:
    return int.from_bytes(data[:4], "little")


def parse_program_account(data: bytes) -> bytes:
    """The programdata address a program account points to."""
    if len(data) < 36:
        raise LoaderError(f"program account is {len(data)} bytes, expected 36")
    if _tag(data) != TAG_PROGRAM:
        raise LoaderError(f"expected loader state Program (tag 2), got tag {_tag(data)}")
    return data[4:36]


def parse_programdata_header(data: bytes) -> ProgramDataHeader:
    """Deploy slot and upgrade authority from the first 45 bytes of a programdata account."""
    if len(data) < PROGRAMDATA_HEADER_LEN:
        raise LoaderError(f"programdata header is {len(data)} bytes, expected {PROGRAMDATA_HEADER_LEN}")
    if _tag(data) != TAG_PROGRAMDATA:
        raise LoaderError(f"expected loader state ProgramData (tag 3), got tag {_tag(data)}")
    slot = int.from_bytes(data[4:12], "little")
    option = data[12]
    if option == 0:
        return ProgramDataHeader(slot, None)
    if option == 1:
        return ProgramDataHeader(slot, data[13:45])
    raise LoaderError(f"bad Option tag {option} for the upgrade authority")


def program_binary(data: bytes) -> tuple[bytes, str]:
    """The deployed ELF without the account's zero padding, and how its end was found.

    The end comes from the ELF's own headers. Stripping trailing zeros would also work most of
    the time, but an ELF can legitimately end in zero bytes (the last section header usually
    does), and a hash of a cut-short binary would never match the same binary built locally.
    rstrip is only the fallback when the bytes do not parse as ELF.
    """
    parse_programdata_header(data)
    body = data[PROGRAMDATA_HEADER_LEN:]
    try:
        return body[:parse_elf(body).extent], "elf headers"
    except ElfError:
        return body.rstrip(b"\0"), "trailing zeros stripped (not a parseable ELF)"
