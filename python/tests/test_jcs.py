"""RFC 8785 / JSON.stringify parity of the canonicalizer."""
import math

import pytest

from fractalai_pqc_verify.jcs import canonicalize


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "0"), (-0.0, "0"), (1.0, "1"), (-1, "-1"), (0.1, "0.1"), (1.5e-7, "1.5e-7"), (1e-6, "0.000001"),
        (1e21, "1e+21"), (1e20, "100000000000000000000"), (123456789012345680000.0, "123456789012345680000"),
        (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"), (2**53 + 1, "9007199254740992"),
        (1.000872452215302, "1.000872452215302"), (822879.84900645, "822879.84900645"),
        (True, "true"), (None, "null"), ("é ", '"é "'), ("\x00\x1f\"\\\n", '"\\u0000\\u001f\\"\\\\\\n"'),
        ("\ud800", '"\\ud800"'),
    ],
)
def test_scalars(value, expected):
    assert canonicalize(value) == expected


def test_key_order_is_utf16_code_units():
    # U+1F600 (surrogates D83D DE00) sorts BEFORE U+FB01 in UTF-16 order, after it in code-point order.
    assert canonicalize({"ﬁ": 1, "\U0001f600": 2, "a": 3}) == '{"a":3,"\U0001f600":2,"ﬁ":1}'


def test_nested_and_compact():
    assert canonicalize({"b": [1, {"d": None, "c": True}], "a": "x"}) == '{"a":"x","b":[1,{"c":true,"d":null}]}'


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_rejected(bad):
    with pytest.raises(ValueError):
        canonicalize(bad)
