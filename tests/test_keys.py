import hashlib
import random

import pytest

from anchor_upgrade_check.base58 import b58decode, b58encode, decode_pubkey
from anchor_upgrade_check.keys import (UPGRADEABLE_LOADER, OnCurveError, anchor_idl_address,
                                       create_program_address, create_with_seed,
                                       find_program_address, is_on_curve)


def test_base58_round_trip_keeps_leading_zeros() -> None:
    rng = random.Random(1)
    for n in (0, 1, 31, 32, 64):
        for lead in (0, 1, 5):
            raw = bytes(lead) + bytes(rng.randrange(256) for _ in range(n))
            assert b58decode(b58encode(raw)) == raw
    assert b58encode(bytes(32)) == "1" * 32


def test_base58_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        b58decode("0OIl")  # characters outside the alphabet
    with pytest.raises(ValueError):
        decode_pubkey(b58encode(bytes(range(1, 65))))  # 64 bytes: a signature, not a key


# Vectors from the Solana SDK's own pubkey tests (program id = the upgradeable loader).
SDK_PDA_VECTORS = [
    ([b"", bytes([1])], "BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe"),
    (["☉".encode(), bytes([0])], "13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19"),
    ([b"Talking", b"Squirrels"], "2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk"),
    ([decode_pubkey("SeedPubey1111111111111111111111111111111111"), bytes([1])],
     "976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL"),
]


@pytest.mark.parametrize("seeds,expected", SDK_PDA_VECTORS)
def test_create_program_address_matches_sdk(seeds: list[bytes], expected: str) -> None:
    got = create_program_address(seeds, decode_pubkey(UPGRADEABLE_LOADER))
    assert b58encode(got) == expected
    assert not is_on_curve(got)


def test_create_with_seed_matches_sdk() -> None:
    got = create_with_seed(bytes(32), "limber chicken: 4/45", bytes(32))
    assert b58encode(got) == "9h1HyLCW5dZnBVap8C5egQ9Z6pHyjsh5MNy83iPqqRuq"


def test_on_curve_control() -> None:
    # The Ed25519 base point (y = 4/5) must be on the curve; otherwise the PDA test proves nothing.
    assert is_on_curve(bytes.fromhex("58" + "66" * 31))


@pytest.mark.parametrize("label,bump,base,idl_address", [
    # Synthetic program ids. Bump 248 means seven candidates were on the curve and skipped.
    # Pinned values were computed once with solders, the Python binding of the Rust SDK.
    (b"toy program", 255, "1850bd4aa47cc7aea7163e3163d9fa372c864e11672e471e9cce9342a3839cba",
     "15d05a75635a925082d4feb72fc4af10cd8d896abdb19b04ab61faa34c24de16"),
    (b"toy program 2", 248, "dfeefd57db19861d448c32e4232c6cfb1c84cd9c9f698bfdb055bb64c3088bfb",
     "1282ad348021999691d13414f562e69629c9c21bd67137bae3ff168cc439f46e"),
])
def test_anchor_idl_address_pinned(label: bytes, bump: int, base: str, idl_address: str) -> None:
    pid = hashlib.sha256(label).digest()
    assert find_program_address([], pid) == (bytes.fromhex(base), bump)
    assert anchor_idl_address(pid).hex() == idl_address


def test_seed_limits_and_illegal_owner() -> None:
    pid = decode_pubkey(UPGRADEABLE_LOADER)
    with pytest.raises(ValueError):
        create_program_address([bytes(33)], pid)
    with pytest.raises(ValueError):
        create_program_address([b"x"] * 17, pid)
    with pytest.raises(ValueError):
        create_with_seed(bytes(32), "s" * 33, pid)
    with pytest.raises(ValueError):
        create_with_seed(bytes(32), "seed", bytes(11) + b"ProgramDerivedAddress")
    with pytest.raises(OnCurveError):
        # Find seeds whose hash is on the curve: create_program_address must refuse them.
        for i in range(256):
            create_program_address([bytes([i])], pid)


def test_cross_check_against_solders() -> None:
    solders = pytest.importorskip("solders.pubkey")
    Pubkey = solders.Pubkey
    rng = random.Random(7)
    for _ in range(200):
        raw = bytes(rng.randrange(256) for _ in range(32))
        assert is_on_curve(raw) == Pubkey(raw).is_on_curve()
    for _ in range(40):
        pid = bytes(rng.randrange(256) for _ in range(32))
        seeds = [bytes(rng.randrange(256) for _ in range(rng.randrange(33))) for _ in range(rng.randrange(4))]
        want, want_bump = Pubkey.find_program_address(seeds, Pubkey(pid))
        got, bump = find_program_address(seeds, pid)
        assert (got, bump) == (bytes(want), want_bump)
        base = Pubkey(pid)
        assert anchor_idl_address(pid) == bytes(
            Pubkey.create_with_seed(Pubkey.find_program_address([], base)[0], "anchor:idl", base))
