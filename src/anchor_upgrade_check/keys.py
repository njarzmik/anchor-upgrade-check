"""Program-derived and seeded addresses, computed the way the Solana runtime computes them.

Pure Python, so the tool needs no compiled SDK. The tests pin the Solana SDK's own vectors and,
when `solders` is installed, cross-check against it.
"""

import hashlib
from collections.abc import Sequence

UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
PDA_MARKER = b"ProgramDerivedAddress"
MAX_SEED_LEN = 32
MAX_SEEDS = 16
ANCHOR_IDL_SEED = "anchor:idl"

_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P


class OnCurveError(ValueError):
    """The hash landed on the Ed25519 curve, so it could have a private key and is not a valid PDA."""


def is_on_curve(key: bytes) -> bool:
    """True if `key` decompresses to an Ed25519 point.

    This mirrors curve25519-dalek's `CompressedEdwardsY::decompress`, which the runtime uses:
    the sign bit is ignored, y is taken mod p (non-canonical encodings are accepted), and the
    point exists when (y^2 - 1) / (d*y^2 + 1) is a square mod p. Matching dalek exactly matters,
    because a different answer here gives a different bump and therefore a different address.
    """
    if len(key) != 32:
        raise ValueError("a key is 32 bytes")
    y = (int.from_bytes(key, "little") & ((1 << 255) - 1)) % _P
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    if v == 0:
        return u == 0
    x2 = u * pow(v, _P - 2, _P) % _P
    return x2 == 0 or pow(x2, (_P - 1) // 2, _P) == 1


def create_program_address(seeds: Sequence[bytes], program_id: bytes) -> bytes:
    """sha256(seeds || program_id || "ProgramDerivedAddress"), rejected if it is on the curve."""
    if len(seeds) > MAX_SEEDS:
        raise ValueError(f"at most {MAX_SEEDS} seeds")
    if any(len(s) > MAX_SEED_LEN for s in seeds):
        raise ValueError(f"a seed is at most {MAX_SEED_LEN} bytes")
    digest = hashlib.sha256(b"".join(seeds) + program_id + PDA_MARKER).digest()
    if is_on_curve(digest):
        raise OnCurveError("derived address is on the curve")
    return digest


def find_program_address(seeds: Sequence[bytes], program_id: bytes) -> tuple[bytes, int]:
    """The first off-curve address, trying bump seeds 255 down to 1 as the SDK does (0 is never tried)."""
    for bump in range(255, 0, -1):
        try:
            return create_program_address([*seeds, bytes([bump])], program_id), bump
        except OnCurveError:
            continue
    raise ValueError("no viable bump seed")


def create_with_seed(base: bytes, seed: str, owner: bytes) -> bytes:
    """sha256(base || seed || owner): the address `SystemProgram.createAccountWithSeed` creates."""
    raw = seed.encode()
    if len(raw) > MAX_SEED_LEN:
        raise ValueError(f"a seed is at most {MAX_SEED_LEN} bytes")
    if owner.endswith(PDA_MARKER):
        raise ValueError("illegal owner: ends with the PDA marker")
    return hashlib.sha256(base + raw + owner).digest()


def anchor_idl_address(program_id: bytes) -> bytes:
    """Where `anchor idl init` stores a program's IDL.

    base = the program's PDA with no seeds; the IDL account = create_with_seed(base, "anchor:idl",
    program_id). It depends only on the program id, so it can be found with no SDK or IDL in hand.
    """
    base, _ = find_program_address([], program_id)
    return create_with_seed(base, ANCHOR_IDL_SEED, program_id)
