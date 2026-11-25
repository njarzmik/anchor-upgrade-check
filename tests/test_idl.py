import json
import zlib

import pytest

from anchor_upgrade_check.idl import (IDL_ACCOUNT_DISC, IdlError, decode_idl_account, is_new_format, items,
                                      pascal_case, snake_case)
from synth import DISC, key, toy_idl


def idl_account(idl: dict, pad: int = 64) -> bytes:
    blob = zlib.compress(json.dumps(idl).encode())
    return IDL_ACCOUNT_DISC + key("idl authority") + len(blob).to_bytes(4, "little") + blob + bytes(pad)


def test_idl_account_discriminator_is_the_one_on_chain() -> None:
    # The first 8 bytes of a real Anchor IDL account. A test that builds its fixture from the
    # same constant it checks cannot catch a wrong constant; this pinned value can.
    assert IDL_ACCOUNT_DISC.hex() == "184662bf3a907b9e"


def test_idl_account_round_trip() -> None:
    acc = decode_idl_account(idl_account(toy_idl()))
    assert acc.idl == toy_idl()
    assert acc.authority == key("idl authority")


@pytest.mark.parametrize("mutate", [
    lambda d: b"\x00" * 8 + d[8:],                                     # wrong account discriminator
    lambda d: d[:40] + (len(d)).to_bytes(4, "little") + d[44:],        # length past the account
    lambda d: d[:44] + b"\xff" * 16 + d[60:],                          # corrupted zlib stream
    lambda d: d[:30],                                                  # shorter than the header
])
def test_idl_account_refuses_bad_data(mutate) -> None:
    with pytest.raises(IdlError):
        decode_idl_account(mutate(idl_account(toy_idl())))


@pytest.mark.parametrize("camel,snake", [
    ("initialize", "initialize"), ("setAuthority", "set_authority"),
    ("buyExactQuoteInV2", "buy_exact_quote_in_v2"), ("HTTPServer", "http_server"), ("v2Data", "v2_data"),
])
def test_snake_case(camel: str, snake: str) -> None:
    assert snake_case(camel) == snake


def test_pascal_case_is_what_anchor_logs() -> None:
    assert pascal_case("set_authority") == pascal_case("setAuthority") == "SetAuthority"


def test_both_idl_formats_give_the_same_discriminators() -> None:
    new, old = toy_idl(new_format=True), toy_idl(new_format=False)
    assert is_new_format(new) and not is_new_format(old)
    got_new = [(i.kind, i.disc) for i in items(new)]
    got_old = [(i.kind, i.disc) for i in items(old)]
    assert got_new == got_old
    assert {i.disc for i in items(old)} == set(DISC.values())
    assert all(i.from_idl for i in items(new)) and not any(i.from_idl for i in items(old))
