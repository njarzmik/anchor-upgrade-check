"""Just enough ELF64 parsing for a deployed sBPF program: its sections and its true length.

Two questions need it. Where does the ELF end inside a zero-padded program account? And which
byte ranges hold code, so an instruction pattern is only counted where an instruction can be?
"""

import struct
from dataclasses import dataclass

EM_BPF = 247
EM_SBPF = 263
SHT_NOBITS = 8
SHF_EXECINSTR = 0x4

_EHDR = struct.Struct("<HHIQQQIHHHHHH")  # fields after the 16-byte e_ident
_PHDR = struct.Struct("<IIQQQQQQ")
_SHDR = struct.Struct("<IIQQQQIIQQ")


class ElfError(ValueError):
    """The bytes are not a well-formed little-endian ELF64 file."""


@dataclass(frozen=True)
class Section:
    name: str
    type: int
    flags: int
    offset: int
    size: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR) and self.type != SHT_NOBITS


@dataclass(frozen=True)
class ElfInfo:
    machine: int
    flags: int
    sections: tuple[Section, ...]
    extent: int  # bytes up to the end of the last header, table or section

    def code_ranges(self) -> list[tuple[int, int, str]]:
        """(start, end, name) of each executable section, in file offsets."""
        return [(s.offset, s.offset + s.size, s.name) for s in self.sections if s.executable]


def _check_span(blob: bytes, start: int, length: int, what: str) -> int:
    end = start + length
    if start < 0 or end > len(blob):
        raise ElfError(f"{what} [{start}, {end}) runs past the end of the file ({len(blob)} bytes)")
    return end


def _section_name(blob: bytes, strtab: Section | None, index: int) -> str:
    if strtab is None or index >= strtab.size:
        return f"#{index}"
    start = strtab.offset + index
    end = blob.find(b"\0", start, strtab.offset + strtab.size)
    return blob[start:end if end >= 0 else strtab.offset + strtab.size].decode("ascii", "replace")


def parse_elf(blob: bytes) -> ElfInfo:
    """Parse the ELF header, program headers and section headers, bounds-checking every offset."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise ElfError("no ELF magic")
    if blob[4] != 2 or blob[5] != 1:
        raise ElfError("not a little-endian ELF64 file")
    (_type, machine, _ver, _entry, phoff, shoff, eflags, _ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = _EHDR.unpack_from(blob, 16)
    extent = 64

    if phnum:
        if phentsize != _PHDR.size:
            raise ElfError(f"program header size {phentsize}, expected {_PHDR.size}")
        extent = max(extent, _check_span(blob, phoff, phnum * phentsize, "program header table"))
        for i in range(phnum):
            p = _PHDR.unpack_from(blob, phoff + i * phentsize)
            extent = max(extent, _check_span(blob, p[2], p[5], f"segment {i}"))

    raw: list[tuple[int, ...]] = []
    if shnum:
        if shentsize != _SHDR.size:
            raise ElfError(f"section header size {shentsize}, expected {_SHDR.size}")
        extent = max(extent, _check_span(blob, shoff, shnum * shentsize, "section header table"))
        raw = [_SHDR.unpack_from(blob, shoff + i * shentsize) for i in range(shnum)]

    bare = [Section("", r[1], r[2], r[4], r[5]) for r in raw]
    for i, s in enumerate(bare):
        if s.type != SHT_NOBITS:
            extent = max(extent, _check_span(blob, s.offset, s.size, f"section {i}"))
    strtab = bare[shstrndx] if 0 < shstrndx < len(bare) else None
    sections = tuple(
        Section(_section_name(blob, strtab, r[0]), s.type, s.flags, s.offset, s.size)
        for r, s in zip(raw, bare)
    )
    return ElfInfo(machine=machine, flags=eflags, sections=sections, extent=extent)
