"""Membership scan: does a program binary contain what its Anchor IDL describes, and nothing more?

What is searched, and why:

- 8-byte discriminators of instructions, events and accounts, in two forms. Contiguous bytes
  cover constants the compiler left in read-only data. The second form is the one dispatch code
  usually compiles to: the 64-bit constant is loaded with an sBPF `lddw`, a 16-byte instruction
  that splits it into two 32-bit immediates with 4 bytes in between. A plain byte search cannot
  see that, so a discriminator that is really there would be reported missing.
- `Instruction: <Name>` log strings, which Anchor's dispatcher prints for every instruction.
  A name in the binary that is not in the IDL is the most direct sign of a new instruction.
- Custom error messages, plus the text right after the last known one: Rust stores the messages
  of an error enum one after another, so messages added at the end of the enum land there.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from . import idl as idlmod
from .elf import ElfError, ElfInfo, parse_elf

LDDW_OPCODE = 0x18
IX_LOG_PREFIX = b"Instruction: "
# Anchor's own IDL-management instructions: compiled in unless the program turns them off, logged
# like user instructions, and listed in no IDL. Found by running the scan on a real binary.
ANCHOR_BUILTIN_LOGS = ("IdlCreateAccount", "IdlResizeAccount", "IdlCloseAccount", "IdlCreateBuffer",
                       "IdlWrite", "IdlSetAuthority", "IdlSetBuffer")
_PRINTABLE_RUN = re.compile(rb"[ -~]{4,}")


def lddw_pattern(disc: bytes) -> re.Pattern[bytes]:
    """`lddw rD, imm64`: 18 | regs | off16=0 | imm_lo32 || 00 | 00 | off16=0 | imm_hi32.

    The constant is little-endian, so imm_lo32 is disc[0:4] and imm_hi32 is disc[4:8]. The regs
    byte holds the destination in its low nibble and src = 0, so it is 0x00..0x09 (r10 is the
    read-only frame pointer and cannot be a destination).
    """
    if len(disc) != 8:
        raise ValueError("lddw carries exactly 8 bytes")
    body = (re.escape(bytes([LDDW_OPCODE])) + b"[\x00-\x09]" + re.escape(b"\0\0" + disc[:4])
            + re.escape(b"\0\0\0\0" + disc[4:]))
    return re.compile(b"(?=" + body + b")", re.DOTALL)


def find_all(blob: bytes, needle: bytes) -> list[int]:
    out, i = [], blob.find(needle)
    while i >= 0:
        out.append(i)
        i = blob.find(needle, i + 1)
    return out


def find_lddw(blob: bytes, disc: bytes, code: list[tuple[int, int, str]] | None) -> list[int]:
    """Offsets of `lddw` instructions loading `disc`.

    With section info, a match counts only inside an executable section and on an 8-byte
    instruction boundary, because the same 16 bytes elsewhere are data, not a load. Without
    section info (`code` is None) every offset counts.
    """
    hits = []
    for m in lddw_pattern(disc).finditer(blob):
        off = m.start()
        if code is None or any(s <= off and off + 16 <= e and (off - s) % 8 == 0 for s, e, _ in code):
            hits.append(off)
    return hits


@dataclass
class DiscResult:
    item: idlmod.Item
    contiguous: list[int] = field(default_factory=list)
    lddw: list[int] = field(default_factory=list)
    skipped: str | None = None

    @property
    def found(self) -> bool:
        return bool(self.contiguous or self.lddw)


@dataclass
class LogResult:
    names: list[str]  # IDL instruction names as Anchor logs them
    occurrences: int = 0
    missing: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)  # text after the prefix, matching no IDL name
    ambiguous: dict[str, list[str]] = field(default_factory=dict)
    builtin: list[str] = field(default_factory=list)  # Anchor's IDL-management instructions


@dataclass
class ErrorResult:
    total: int = 0
    missing: list[tuple[int, str, str]] = field(default_factory=list)
    last_code: int | None = None
    after_last: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    binary_len: int
    elf: ElfInfo | None
    elf_note: str
    idl_name: str
    new_format: bool
    discs: list[DiscResult]
    logs: LogResult
    errors: ErrorResult

    def failures(self) -> list[str]:
        """Everything that makes the scan fail. Empty means the binary matched the IDL."""
        out = []
        for d in self.discs:
            if d.skipped:
                out.append(f"{d.item.kind} {d.item.name}: not checked ({d.skipped})")
            elif not d.found:
                out.append(f"{d.item.kind} {d.item.name}: discriminator {d.item.disc.hex()} not found")
        if self.logs.occurrences:
            out += [f"instruction {n}: no 'Instruction: {n}' log string" for n in self.logs.missing]
        out += [f"'Instruction: ' followed by {t!r} starts with no IDL instruction name" for t in self.logs.unknown]
        out += [f"'Instruction: {n}' appears {len(t)} times; the IDL explains one" for n, t in self.logs.ambiguous.items()]
        out += [f"error {c} {n}: message not found" for c, n, _ in self.errors.missing]
        return out


def _scan_discs(blob: bytes, items: list[idlmod.Item], code: list[tuple[int, int, str]] | None) -> list[DiscResult]:
    out = []
    for it in items:
        if len(it.disc) != 8:
            out.append(DiscResult(it, skipped=f"{len(it.disc)}-byte discriminator, only 8-byte ones are searched"))
            continue
        out.append(DiscResult(it, find_all(blob, it.disc), find_lddw(blob, it.disc, code)))
    return out


def _scan_logs(blob: bytes, ix_names: list[str], tail_len: int = 48) -> LogResult:
    """Match each `Instruction: ` occurrence to the longest IDL name its text starts with.

    Rust packs string literals with no separator, so the text after a name is usually the next
    literal and the end of the name cannot be read off the bytes. Two consequences: an unknown
    name is shown with whatever follows it, and when one IDL name matches several occurrences
    (`Deposit` and a new `DepositAll`, say), that is a finding, because the dispatcher logs each
    instruction once and the IDL only explains one of them.
    """
    res = LogResult(names=ix_names)
    by_name: dict[str, list[str]] = defaultdict(list)
    candidates = [*ix_names, *ANCHOR_BUILTIN_LOGS]
    for off in find_all(blob, IX_LOG_PREFIX):
        res.occurrences += 1
        tail = blob[off + len(IX_LOG_PREFIX): off + len(IX_LOG_PREFIX) + tail_len]
        text = re.sub(rb"[^ -~]", b".", tail).decode()
        best = max((n for n in candidates if tail.startswith(n.encode())), key=len, default=None)
        if best is None:
            res.unknown.append(text)
        else:
            by_name[best].append(text)
    res.missing = [n for n in ix_names if n not in by_name]
    res.ambiguous = {n: t for n, t in by_name.items() if len(t) > 1}
    res.builtin = [n for n in ANCHOR_BUILTIN_LOGS if n in by_name and n not in ix_names]
    return res


def _scan_errors(blob: bytes, errs: list[tuple[int, str, str]], context: int) -> ErrorResult:
    res = ErrorResult(total=len(errs))
    placed = []
    for code, name, msg in errs:
        pos = blob.find(msg.encode())
        if pos < 0:
            res.missing.append((code, name, msg))
        else:
            placed.append((pos + len(msg.encode()), code))
    if placed:
        end, res.last_code = max(placed)
        res.after_last = [m.group().decode() for m in _PRINTABLE_RUN.finditer(blob[end:end + context])]
    return res


def scan(blob: bytes, idl: dict[str, Any], context: int = 300) -> ScanReport:
    """Run every check. `context` is how many bytes after the last known error message to show."""
    try:
        elf: ElfInfo | None = parse_elf(blob)
        code = elf.code_ranges()
        note = f"ELF64, machine {elf.machine}, e_flags {elf.flags:#x}, code in {[n for _, _, n in code]}"
        if not code:
            code, note = None, note + "; no executable section, so lddw is searched everywhere"
    except ElfError as e:
        elf, code = None, None
        note = f"not parsed as ELF ({e}); lddw searched at every offset"
    names = [idlmod.pascal_case(ix["name"]) for ix in idl.get("instructions") or []]
    return ScanReport(
        binary_len=len(blob),
        elf=elf,
        elf_note=note,
        idl_name=idlmod.idl_name(idl),
        new_format=idlmod.is_new_format(idl),
        discs=_scan_discs(blob, idlmod.items(idl), code),
        logs=_scan_logs(blob, names),
        errors=_scan_errors(blob, idlmod.errors(idl), context),
    )


def _where(off: int, elf: ElfInfo | None) -> str:
    if elf:
        for s in elf.sections:
            if s.size and s.offset <= off < s.offset + s.size and s.name:
                return f"{s.name}+{off - s.offset:#x}"
    return f"{off:#x}"


def render(r: ScanReport) -> str:
    """Human-readable report. Every finding is listed, not just a count."""
    fmt = "Anchor 0.30+ (discriminators from the IDL)" if r.new_format else \
        "older Anchor (discriminators recomputed from names)"
    lines = [f"binary   {r.binary_len:,} bytes; {r.elf_note}", f"idl      {r.idl_name}, {fmt}", "",
             "discriminators (contiguous bytes / sBPF lddw immediate pair)"]
    width = max([12, *(len(d.item.name) for d in r.discs)])
    for d in r.discs:
        if d.skipped:
            state = f"skipped: {d.skipped}"
        elif not d.found:
            state = "MISSING"
        else:
            parts = [f"contiguous at {', '.join(_where(o, r.elf) for o in d.contiguous[:3])}"] if d.contiguous else []
            parts += [f"lddw at {', '.join(_where(o, r.elf) for o in d.lddw[:3])}"] if d.lddw else []
            state = "; ".join(parts)
        lines.append(f"  {d.item.kind:<11} {d.item.name:<{width}}  {d.item.disc.hex()}  {state}")

    lg = r.logs
    lines += ["", f"instruction-name logs ('Instruction: <Name>'): {lg.occurrences} in the binary, "
                  f"{len(lg.names) - len(lg.missing)}/{len(lg.names)} IDL names found"]
    if not lg.occurrences:
        lines.append("  none at all: built without instruction-name logging? Not counted as a failure.")
    lines += [f"  missing:     {n}" for n in lg.missing] if lg.occurrences else []
    lines += [f"  not in IDL:  {t!r}" for t in lg.unknown]
    for n, tails in lg.ambiguous.items():
        lines.append(f"  ambiguous:   {n} matches {len(tails)} occurrences: {tails!r}")
    if lg.builtin:
        lines.append(f"  Anchor IDL-management instructions (in no IDL, not counted): {', '.join(lg.builtin)}")

    er = r.errors
    lines += ["", f"error messages: {er.total - len(er.missing)}/{er.total} found"]
    lines += [f"  missing:     {c} {n}: {m!r}" for c, n, m in er.missing]
    if er.last_code is not None:
        lines.append(f"  text after the last-placed message (code {er.last_code}); new messages would be here:")
        lines += [f"    {s!r}" for s in er.after_last] or ["    (nothing printable)"]

    fails = r.failures()
    lines += ["", f"RESULT: {'MATCH' if not fails else f'{len(fails)} finding(s)'}"]
    lines += [f"  - {f}" for f in fails]
    return "\n".join(lines)
