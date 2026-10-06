"""RFC 8785 (JCS) canonical JSON, byte-for-byte compatible with the Node reference (`profiles.mjs`).

The reference serializes with ``JSON.stringify`` for scalars and sorts object keys with the default
JavaScript sort (UTF-16 code-unit order). This module reproduces that exactly in Python:

* object keys sorted by UTF-16 code units (RFC 8785 section 3.2.3), not by Python code points;
* strings escaped the way ``JSON.stringify`` does (``\\b \\f \\n \\r \\t``, other C0 controls as
  lowercase ``\\u00xx``, lone surrogates as ``\\udxxx``, everything else literal UTF-8);
* numbers formatted with the ECMAScript ``Number::toString`` algorithm (RFC 8785 section 3.2.2.3),
  including the exponent forms (``1e+21``, ``1e-7``) and ``-0 -> 0``;
* integers outside the IEEE-754 safe range are rendered as the double JavaScript would have parsed,
  so a receipt hashes to the same bytes in both languages;
* NaN / Infinity are rejected (RFC 8785 forbids them).
"""
from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = ["canonicalize", "canonicalize_bytes"]

_MAX_SAFE_INT = 2**53 - 1
_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _join_surrogate_pairs(s: str) -> str:
    # A Python str may hold a high+low surrogate as two code points; JavaScript sees one character.
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
    return s


def _string(s: str) -> str:
    s = _join_surrogate_pairs(s)
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
            continue
        cp = ord(ch)
        if cp < 0x20 or 0xD800 <= cp <= 0xDFFF:  # C0 controls and lone surrogates
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(x: float) -> str:
    if not math.isfinite(x):
        raise ValueError("JCS: non-finite number (NaN/Infinity forbidden by RFC 8785)")
    if x == 0:
        return "0"  # also maps -0 to "0", as JSON.stringify does
    sign = "-" if x < 0 else ""
    # repr() yields the shortest round-tripping decimal, the same digit string ECMAScript picks.
    _, digits_t, exp = Decimal(repr(abs(x))).as_tuple()
    digits = "".join(map(str, digits_t)).rstrip("0") or "0"
    stripped = len("".join(map(str, digits_t))) - len(digits)
    k = len(digits)
    n = exp + stripped + k  # value = 0.digits * 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def canonicalize(value: Any) -> str:
    """Return the canonical JSON text of ``value`` (dict / list / str / int / float / bool / None)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            return _number(float(value))  # what JavaScript would have parsed and printed
        return str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"JCS: object keys must be strings, got {type(k).__name__}")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(k) + ":" + canonicalize(value[k]) for k in keys) + "}"
    raise TypeError(f"JCS: unsupported {type(value).__name__}")


def canonicalize_bytes(value: Any) -> bytes:
    """UTF-8 bytes of :func:`canonicalize` (lone surrogates are already escaped, so this never fails)."""
    return canonicalize(value).encode("utf-8")
