import struct

import pytest

from anchor_upgrade_check.elf import ElfError, parse_elf
from anchor_upgrade_check.loader import (LoaderError, parse_program_account, parse_programdata_header,
                                         program_binary)
from synth import build_elf, key, lddw, programdata_bytes, toy_binary


def test_programdata_header_with_and_without_authority() -> None:
    hdr = parse_programdata_header(programdata_bytes(123_456_789, key("authority")))
    assert hdr.slot == 123_456_789 and hdr.authority == key("authority")
    frozen = parse_programdata_header(programdata_bytes(5, None))
    assert frozen.slot == 5 and frozen.authority is None


@pytest.mark.parametrize("data", [
    programdata_bytes(1, None)[:44],                        # short
    (2).to_bytes(4, "little") + programdata_bytes(1, None)[4:],  # a Program account, not ProgramData
    programdata_bytes(1, None)[:12] + b"\x02" + bytes(32),   # Option tag 2 does not exist
])
def test_programdata_header_refuses_bad_data(data: bytes) -> None:
    with pytest.raises(LoaderError):
        parse_programdata_header(data)


def test_program_account() -> None:
    assert parse_program_account((2).to_bytes(4, "little") + key("pd")) == key("pd")
    with pytest.raises(LoaderError):
        parse_program_account((3).to_bytes(4, "little") + key("pd"))


def test_binary_end_comes_from_the_elf_not_from_stripping_zeros() -> None:
    elf = toy_binary()
    assert elf.endswith(bytes(8))  # this ELF legitimately ends in zero bytes
    got, how = program_binary(programdata_bytes(9, key("a"), elf, pad=4096))
    assert got == elf and how == "elf headers"
    # Control: the naive method cuts the real binary short, so its hash would never match a local build.
    assert len(elf.rstrip(b"\0")) < len(elf)


def test_non_elf_body_falls_back_to_stripping_zeros() -> None:
    got, how = program_binary(programdata_bytes(9, None, b"not an elf\x00\x07", pad=100))
    assert got == b"not an elf\x00\x07" and "not a parseable ELF" in how


def test_elf_sections_and_code_ranges() -> None:
    info = parse_elf(build_elf(lddw(1, b"12345678"), b"data"))
    assert [s.name for s in info.sections] == ["", ".text", ".rodata", ".shstrtab"]
    (start, end, name), = info.code_ranges()
    assert (end - start, name) == (16, ".text")


def test_elf_refuses_out_of_bounds_tables() -> None:
    elf = bytearray(build_elf(b"\x95" + bytes(7), b"x"))
    with pytest.raises(ElfError):
        parse_elf(bytes(elf[:-10]))  # section header table cut short
    shoff = struct.unpack_from("<Q", elf, 40)[0]
    struct.pack_into("<Q", elf, shoff + 64 + 32, 1 << 20)  # .text size far past the end
    with pytest.raises(ElfError):
        parse_elf(bytes(elf))
    with pytest.raises(ElfError):
        parse_elf(b"\x7fELF" + bytes([1, 1]) + bytes(58))  # ELF32
