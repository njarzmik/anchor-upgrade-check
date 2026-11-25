import struct

from anchor_upgrade_check.idl import pascal_case
from anchor_upgrade_check.scan import render, scan
from synth import DISC, ERRORS, INSTRUCTIONS, MOV0, build_elf, lddw, toy_binary, toy_idl


def result(report, name: str):
    return next(d for d in report.discs if d.item.name == name)


def test_matching_binary_passes() -> None:
    report = scan(toy_binary(), toy_idl())
    assert report.failures() == []
    assert "RESULT: MATCH" in render(report)


def test_missing_discriminator_is_reported() -> None:
    # Planted error: withdraw's discriminator is left out of the binary (its log string stays).
    report = scan(toy_binary(omit=("withdraw",)), toy_idl())
    assert report.failures() == [f"instruction withdraw: discriminator {DISC['withdraw'].hex()} not found"]
    assert "MISSING" in render(report)


def test_lddw_split_constant_is_invisible_to_a_byte_search() -> None:
    blob = toy_binary()
    assert DISC["initialize"] not in blob  # a plain byte search would call it missing
    hit = result(scan(blob, toy_idl()), "initialize")
    assert hit.lddw and not hit.contiguous
    hit = result(scan(blob, toy_idl()), "deposit")
    assert hit.contiguous and not hit.lddw


def test_lddw_off_an_instruction_boundary_does_not_count() -> None:
    misaligned = toy_binary(lddw_items=(), omit=("initialize",), text_extra=b"\x00" * 4 + lddw(1, DISC["initialize"]) + b"\x00" * 4)
    assert not result(scan(misaligned, toy_idl()), "initialize").found
    aligned = toy_binary(lddw_items=(), omit=("initialize",), text_extra=lddw(1, DISC["initialize"]))
    assert result(scan(aligned, toy_idl()), "initialize").found


def test_lddw_bytes_in_a_data_section_do_not_count() -> None:
    blob = toy_binary(lddw_items=(), omit=("initialize",), rodata_extra=bytes(8) + lddw(1, DISC["initialize"]))
    assert not result(scan(blob, toy_idl()), "initialize").found


def test_without_a_section_table_every_offset_counts() -> None:
    blob = b"no elf here" + lddw(3, DISC["initialize"])
    report = scan(blob, toy_idl())
    assert result(report, "initialize").lddw == [11]
    assert "not parsed as ELF" in report.elf_note


def test_unknown_instruction_name_is_reported() -> None:
    names = [pascal_case(n) for n in INSTRUCTIONS] + ["Migrate"]
    report = scan(toy_binary(log_names=names), toy_idl())
    assert len(report.logs.unknown) == 1 and report.logs.unknown[0].startswith("MigrateProgram log")
    assert any("Migrate" in f for f in report.failures())


def test_name_that_extends_a_known_name_is_not_hidden() -> None:
    # 'DepositAll' starts with the known 'Deposit'; a longest-prefix match alone would accept it.
    names = [pascal_case(n) for n in INSTRUCTIONS] + ["DepositAll"]
    report = scan(toy_binary(log_names=names), toy_idl())
    assert list(report.logs.ambiguous) == ["Deposit"]
    assert any("appears 2 times" in f for f in report.failures())


def test_anchor_builtin_instructions_are_listed_not_failed() -> None:
    # Found on a real binary: Anchor's IDL-management instructions log names that no IDL lists.
    builtins = ["IdlCreateAccount", "IdlResizeAccount", "IdlWrite", "IdlSetBuffer"]
    report = scan(toy_binary(log_names=[pascal_case(n) for n in INSTRUCTIONS] + builtins), toy_idl())
    assert report.failures() == [] and report.logs.builtin == ["IdlCreateAccount", "IdlResizeAccount",
                                                               "IdlWrite", "IdlSetBuffer"]
    assert "IDL-management" in render(report)
    # Control: a name that merely starts like one is still unknown.
    report = scan(toy_binary(log_names=[pascal_case(n) for n in INSTRUCTIONS] + ["IdlMigrate"]), toy_idl())
    assert len(report.logs.unknown) == 1


def test_missing_and_new_error_messages() -> None:
    msgs = [m for _, _, m in ERRORS if not m.startswith("Vault")] + ["Fees exceed the cap"]
    report = scan(toy_binary(error_msgs=msgs), toy_idl())
    assert [c for c, _, _ in report.errors.missing] == [6001]
    assert report.errors.after_last[0].startswith("Fees exceed the cap")
    assert "error 6001 VaultLocked: message not found" in report.failures()


def test_binary_without_instruction_logs_is_a_note_not_a_failure() -> None:
    report = scan(toy_binary(log_names=[]), toy_idl())
    assert report.logs.occurrences == 0 and report.failures() == []
    assert "none at all" in render(report)


def test_older_idl_format_scans_the_same() -> None:
    report = scan(toy_binary(), toy_idl(new_format=False))
    assert report.failures() == [] and not report.new_format
    report = scan(toy_binary(omit=("set_authority",)), toy_idl(new_format=False))
    assert report.failures() == [f"instruction setAuthority: discriminator {DISC['set_authority'].hex()} not found"]


def test_short_discriminator_is_not_checked_and_not_passed() -> None:
    idl = toy_idl()
    idl["instructions"][0]["discriminator"] = [1]
    report = scan(toy_binary(), idl)
    assert result(report, "initialize").skipped
    assert any("not checked" in f for f in report.failures())


def test_elf_without_an_executable_section_falls_back_to_every_offset() -> None:
    blob = bytearray(build_elf(MOV0 + lddw(1, DISC["initialize"]), b""))
    shoff = struct.unpack_from("<Q", blob, 40)[0]
    struct.pack_into("<Q", blob, shoff + 64 + 8, 0x2)  # .text flags: ALLOC only, EXECINSTR cleared
    report = scan(bytes(blob), toy_idl())
    assert "no executable section" in report.elf_note
    assert result(report, "initialize").lddw
