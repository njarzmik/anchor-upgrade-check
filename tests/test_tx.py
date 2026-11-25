import pytest

from anchor_upgrade_check.tx import (AccountMeta, Instruction, TxError, build_legacy_tx, decode_compact_u16,
                                     encode_compact_u16, parse_tx, zero_signatures)
from synth import key

VECTORS = [(0, "00"), (127, "7f"), (128, "8001"), (16383, "ff7f"), (16384, "808001"), (65535, "ffff03")]


@pytest.mark.parametrize("value,hexed", VECTORS)
def test_compact_u16(value: int, hexed: str) -> None:
    assert encode_compact_u16(value).hex() == hexed
    assert decode_compact_u16(bytes.fromhex(hexed), 0) == (value, len(hexed) // 2)


@pytest.mark.parametrize("hexed", ["8000", "ffff04", "808080", "80"])
def test_compact_u16_refuses_non_canonical(hexed: str) -> None:
    with pytest.raises(TxError):
        decode_compact_u16(bytes.fromhex(hexed), 0)


def toy_ix() -> list[Instruction]:
    accounts = (AccountMeta(key("vault"), False, True), AccountMeta(key("authority"), True, False),
                AccountMeta(key("config"), False, False))
    return [Instruction(key("program"), accounts, bytes.fromhex("ffffffffffffffff"))]


def test_legacy_build_round_trip_and_key_order() -> None:
    raw = build_legacy_tx(key("payer"), toy_ix())
    p = parse_tx(raw)
    assert p.version == "legacy" and p.signatures == (bytes(64), bytes(64))
    assert p.header == (2, 1, 2)  # payer + authority sign; authority, config, program are readonly
    assert p.account_keys[:3] == (key("payer"), key("authority"), key("vault"))
    assert set(p.account_keys[3:]) == {key("config"), key("program")}
    (prog, accs, data), = p.instructions
    assert p.account_keys[prog] == key("program")
    assert [p.account_keys[i] for i in accs] == [key("vault"), key("authority"), key("config")]
    assert data == bytes.fromhex("ffffffffffffffff")


def test_legacy_build_matches_solders_byte_for_byte() -> None:
    sp = pytest.importorskip("solders.pubkey")
    si = pytest.importorskip("solders.instruction")
    sm = pytest.importorskip("solders.message")
    sh = pytest.importorskip("solders.hash")
    ix = toy_ix()[0]
    metas = [si.AccountMeta(sp.Pubkey(m.pubkey), m.is_signer, m.is_writable) for m in ix.accounts]
    msg = sm.Message.new_with_blockhash([si.Instruction(sp.Pubkey(ix.program_id), ix.data, metas)],
                                        sp.Pubkey(key("payer")), sh.Hash(bytes(32)))
    p = parse_tx(build_legacy_tx(key("payer"), toy_ix()))
    assert build_legacy_tx(key("payer"), toy_ix())[1 + 64 * len(p.signatures):] == bytes(msg)


def signed_copy(raw: bytes) -> bytes:
    """The same transaction with non-zero bytes where the signatures go, as if signed."""
    n = raw[0]
    return raw[:1] + bytes([0xAB]) * (64 * n) + raw[1 + 64 * n:]


def test_zero_signatures_blanks_only_the_signatures() -> None:
    raw = build_legacy_tx(key("payer"), toy_ix())
    signed = signed_copy(raw)
    assert signed != raw
    blank, p = zero_signatures(signed)
    assert blank == raw and len(p.signatures) == 2


def v0_tx() -> bytes:
    """A hand-built v0 transaction with one address lookup table."""
    msg = bytes([0x80, 1, 0, 1]) + bytes([2]) + key("payer") + key("program") + key("blockhash")
    msg += bytes([1, 1, 1, 0, 2]) + b"\x01\x02"          # one ix: program 1, account 0, 2 data bytes
    msg += bytes([1]) + key("table") + bytes([1, 3]) + bytes([2, 4, 5])
    return bytes([1]) + bytes([0xCD]) * 64 + msg


def test_v0_parses_and_blanks() -> None:
    blank, p = zero_signatures(v0_tx())
    assert p.version == "v0" and blank[1:65] == bytes(64) and blank[65:] == v0_tx()[65:]


@pytest.mark.parametrize("raw", [
    bytes([0x80]) + bytes(100),            # not legacy / v0: signatures are not first
    v0_tx()[:-1],                          # truncated
    v0_tx() + b"\x00",                     # trailing byte
    v0_tx()[:65] + bytes([0x81]) + v0_tx()[66:],  # message version 1 in a v0-style frame
    bytes([2]) + v0_tx()[1:65] * 2 + v0_tx()[65:],  # two signatures, header asks for one
])
def test_parse_refuses_what_it_cannot_parse_exactly(raw: bytes) -> None:
    with pytest.raises(TxError):
        parse_tx(raw)


def test_size_limit() -> None:
    big = [Instruction(key("program"), (), bytes(1300))]
    with pytest.raises(TxError):
        build_legacy_tx(key("payer"), big)
