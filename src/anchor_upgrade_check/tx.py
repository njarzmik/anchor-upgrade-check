"""Solana transaction wire format: enough to build an unsigned legacy transaction for simulation,
and to parse legacy and v0 transactions well enough to blank their signatures safely.

The simulate command never signs anything. It sends zero signatures with signature verification
off, so no private key is ever loaded, and a transaction it sends could not be submitted by
anyone who saw it.
"""

from dataclasses import dataclass

MAX_TX_SIZE = 1232
SIGNATURE_LEN = 64


class TxError(ValueError):
    """The bytes are not a transaction this module can parse exactly."""


def encode_compact_u16(n: int) -> bytes:
    """Solana's 'shortvec': 7 bits per byte, low bits first, high bit = more bytes follow."""
    if not 0 <= n <= 0xFFFF:
        raise ValueError("compact-u16 holds 0..65535")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_compact_u16(buf: bytes, pos: int) -> tuple[int, int]:
    """(value, next position). Rejects overlong and out-of-range encodings, as the runtime does."""
    value = 0
    for i in range(3):
        if pos + i >= len(buf):
            raise TxError("truncated compact-u16")
        b = buf[pos + i]
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            if (b == 0 and i > 0) or value > 0xFFFF:
                raise TxError("non-canonical compact-u16")
            return value, pos + i + 1
    raise TxError("compact-u16 longer than 3 bytes")


@dataclass(frozen=True)
class AccountMeta:
    pubkey: bytes
    is_signer: bool
    is_writable: bool


@dataclass(frozen=True)
class Instruction:
    program_id: bytes
    accounts: tuple[AccountMeta, ...]
    data: bytes


@dataclass(frozen=True)
class ParsedTx:
    signatures: tuple[bytes, ...]
    version: str  # "legacy" or "v0"
    header: tuple[int, int, int]  # required signatures, readonly signed, readonly unsigned
    account_keys: tuple[bytes, ...]
    blockhash: bytes
    instructions: tuple[tuple[int, tuple[int, ...], bytes], ...]  # (program index, account indexes, data)
    message_offset: int


def _compile_keys(payer: bytes, ixs: list[Instruction]) -> list[tuple[bytes, bool, bool]]:
    """Merge account flags and order keys as the SDK does: payer first, then writable signers,
    readonly signers, writable non-signers, readonly non-signers, each group sorted by key."""
    flags: dict[bytes, list[bool]] = {payer: [True, True]}
    for ix in ixs:
        for m in ix.accounts:
            f = flags.setdefault(m.pubkey, [False, False])
            f[0] |= m.is_signer
            f[1] |= m.is_writable
        flags.setdefault(ix.program_id, [False, False])
    rest = [(k, s, w) for k, (s, w) in flags.items() if k != payer]
    group = {(True, True): 0, (True, False): 1, (False, True): 2, (False, False): 3}
    rest.sort(key=lambda t: (group[(t[1], t[2])], t[0]))
    return [(payer, True, True), *rest]


def build_legacy_tx(payer: bytes, ixs: list[Instruction], blockhash: bytes = bytes(32)) -> bytes:
    """An unsigned legacy transaction: one zero signature per required signer.

    The blockhash defaults to zeros because simulation is asked to replace it.
    """
    keys = _compile_keys(payer, ixs)
    index = {k: i for i, (k, _, _) in enumerate(keys)}
    n_sig = sum(1 for _, s, _ in keys if s)
    ro_signed = sum(1 for _, s, w in keys if s and not w)
    ro_unsigned = sum(1 for _, s, w in keys if not s and not w)
    msg = bytearray([n_sig, ro_signed, ro_unsigned])
    msg += encode_compact_u16(len(keys)) + b"".join(k for k, _, _ in keys)
    msg += blockhash + encode_compact_u16(len(ixs))
    for ix in ixs:
        msg.append(index[ix.program_id])
        msg += encode_compact_u16(len(ix.accounts)) + bytes(index[m.pubkey] for m in ix.accounts)
        msg += encode_compact_u16(len(ix.data)) + ix.data
    raw = encode_compact_u16(n_sig) + bytes(SIGNATURE_LEN * n_sig) + bytes(msg)
    if len(raw) > MAX_TX_SIZE:
        raise TxError(f"transaction is {len(raw)} bytes, over the {MAX_TX_SIZE}-byte limit")
    return raw


def _take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if pos + n > len(buf):
        raise TxError("truncated transaction")
    return buf[pos:pos + n], pos + n


def parse_tx(raw: bytes) -> ParsedTx:
    """Parse a legacy or v0 transaction to its last byte; anything else is refused.

    Both formats put the signatures first. A first byte of 0x80 or more cannot be a signature
    count of a valid transaction, so it means a format with a different layout; rather than
    guess where its signatures are, it is refused.
    """
    if raw and raw[0] & 0x80:
        raise TxError(f"first byte {raw[0]:#04x}: not a legacy or v0 transaction")
    n_sig, pos = decode_compact_u16(raw, 0)
    sigs = []
    for _ in range(n_sig):
        s, pos = _take(raw, pos, SIGNATURE_LEN)
        sigs.append(s)
    msg_off = pos
    version = "legacy"
    if pos < len(raw) and raw[pos] & 0x80:
        if raw[pos] & 0x7F != 0:
            raise TxError(f"message version {raw[pos] & 0x7F} is not supported")
        version, pos = "v0", pos + 1
    hdr, pos = _take(raw, pos, 3)
    if hdr[0] != n_sig:
        raise TxError(f"header requires {hdr[0]} signatures but {n_sig} are present")
    n_keys, pos = decode_compact_u16(raw, pos)
    keys = []
    for _ in range(n_keys):
        k, pos = _take(raw, pos, 32)
        keys.append(k)
    blockhash, pos = _take(raw, pos, 32)
    n_ix, pos = decode_compact_u16(raw, pos)
    ixs = []
    for _ in range(n_ix):
        prog, pos = _take(raw, pos, 1)
        n_acc, pos = decode_compact_u16(raw, pos)
        acc, pos = _take(raw, pos, n_acc)
        n_data, pos = decode_compact_u16(raw, pos)
        data, pos = _take(raw, pos, n_data)
        ixs.append((prog[0], tuple(acc), data))
    if version == "v0":
        n_lut, pos = decode_compact_u16(raw, pos)
        for _ in range(n_lut):
            _, pos = _take(raw, pos, 32)
            for _ in range(2):  # writable indexes, then readonly indexes
                n, pos = decode_compact_u16(raw, pos)
                _, pos = _take(raw, pos, n)
    if pos != len(raw):
        raise TxError(f"{len(raw) - pos} unexpected bytes after the message")
    return ParsedTx(tuple(sigs), version, (hdr[0], hdr[1], hdr[2]), tuple(keys), blockhash, tuple(ixs), msg_off)


def zero_signatures(raw: bytes) -> tuple[bytes, ParsedTx]:
    """The same transaction with every signature replaced by 64 zero bytes."""
    p = parse_tx(raw)
    start = p.message_offset - SIGNATURE_LEN * len(p.signatures)
    blanked = raw[:start] + bytes(SIGNATURE_LEN * len(p.signatures)) + raw[p.message_offset:]
    return blanked, p
