"""Base58 with the Bitcoin alphabet: the text form of Solana keys and signatures.

Written out here (a dozen lines) so the package has no third-party dependency.
"""

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def b58encode(data: bytes) -> str:
    """Encode bytes. Each leading zero byte becomes a leading '1'."""
    n = int.from_bytes(data, "big")
    digits = []
    while n:
        n, r = divmod(n, 58)
        digits.append(ALPHABET[r])
    zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * zeros + "".join(reversed(digits))


def b58decode(text: str) -> bytes:
    """Decode text. Raises ValueError on a character outside the alphabet."""
    n = 0
    for c in text:
        try:
            n = n * 58 + _INDEX[c]
        except KeyError:
            raise ValueError(f"not a base58 character: {c!r}") from None
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + body


def decode_pubkey(text: str) -> bytes:
    """Decode a public key and insist on 32 bytes, so a pasted signature or typo fails here."""
    raw = b58decode(text.strip())
    if len(raw) != 32:
        raise ValueError(f"a public key is 32 bytes; {text!r} decodes to {len(raw)}")
    return raw
