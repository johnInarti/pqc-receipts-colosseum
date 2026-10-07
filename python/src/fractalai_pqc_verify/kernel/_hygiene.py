"""Input/output hygiene — Python mirror of kernel/src/hygiene.mjs (spec/TRUST-KERNEL.md §8).

Strict RFC 8259 JSON: duplicate keys, lone surrogates, NaN/Infinity, a BOM, trailing data, depth > 32,
> 100 000 nodes and > 2 MiB are REJECTED (never resolved). Canonical base64 only. Bounded HTTPS fetch.
"""
from __future__ import annotations

import base64
import json
import math
import re
import urllib.error
import urllib.request
from typing import Any

from ._codes import C, KernelError

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_STRING = 1024 * 1024
MAX_SAFE = 2**53 - 1


def _pairs(ps):
    d: dict = {}
    for k, v in ps:
        if k in d:
            raise KernelError(C.JSON_DUPLICATE_KEY, f"duplicate key {json.dumps(k)[:80]}")
        d[k] = v
    return d


def _const(name):
    raise KernelError(C.JSON_INVALID, f"non-JSON constant {name}")


def _float(s):
    v = float(s)
    if not math.isfinite(v):
        raise KernelError(C.JSON_INVALID, "number out of range")
    return v


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def assert_json_value(v: Any) -> Any:
    """Iterative limits check (depth, nodes, string length, lone surrogates) — never recursion."""
    nodes = 0
    stack = [(v, 0)]
    while stack:
        x, d = stack.pop()
        if d > MAX_DEPTH:
            raise KernelError(C.JSON_TOO_DEEP, f"nesting depth exceeds {MAX_DEPTH}")
        nodes += 1
        if nodes > MAX_NODES:
            raise KernelError(C.JSON_TOO_LARGE, f"more than {MAX_NODES} JSON nodes")
        if x is None or isinstance(x, bool):
            continue
        if isinstance(x, (int, float)):
            if isinstance(x, float) and not math.isfinite(x):
                raise KernelError(C.INPUT_SHAPE, "non-finite number")
            continue
        if isinstance(x, str):
            if len(x) > MAX_STRING:
                raise KernelError(C.JSON_TOO_LARGE, "string too long")
            if _has_surrogate(x):
                raise KernelError(C.JSON_LONE_SURROGATE, "lone surrogate in string")
            continue
        if isinstance(x, list):
            stack.extend((y, d + 1) for y in x)
            continue
        if isinstance(x, dict):
            for k, y in x.items():
                if not isinstance(k, str):
                    raise KernelError(C.INPUT_SHAPE, "non-string key")
                if _has_surrogate(k):
                    raise KernelError(C.JSON_LONE_SURROGATE, "lone surrogate in key")
                stack.append((y, d + 1))
            continue
        raise KernelError(C.INPUT_SHAPE, f"unsupported JSON type {type(x).__name__}")
    return v


def parse_json_strict(data: str | bytes) -> Any:
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_JSON_BYTES:
            raise KernelError(C.JSON_TOO_LARGE, f"input exceeds {MAX_JSON_BYTES} bytes")
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise KernelError(C.JSON_INVALID, "input is not valid UTF-8") from None
    elif isinstance(data, str):
        text = data
    else:
        raise KernelError(C.JSON_INVALID, "input is not text")
    if len(text) > MAX_JSON_BYTES or len(text.encode("utf-8", "surrogatepass")) > MAX_JSON_BYTES:
        raise KernelError(C.JSON_TOO_LARGE, f"input exceeds {MAX_JSON_BYTES} bytes")
    if text.startswith("\ufeff"):
        raise KernelError(C.JSON_INVALID, "byte-order mark not allowed")
    try:
        v = json.loads(text, object_pairs_hook=_pairs, parse_constant=_const, parse_float=_float)
    except KernelError:
        raise
    except RecursionError:
        raise KernelError(C.JSON_TOO_DEEP, "nesting too deep") from None
    except (ValueError, TypeError) as e:
        raise KernelError(C.JSON_INVALID, str(e)[:120]) from None
    return assert_json_value(v)


def is_plain_object(v) -> bool:
    return isinstance(v, dict)


def own(o, k) -> bool:
    return isinstance(o, dict) and k in o


def is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_safe_int(v) -> bool:
    """ECMAScript Number.isSafeInteger over a JSON-parsed value (5.0 counts, True does not)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return -MAX_SAFE <= v <= MAX_SAFE
    if isinstance(v, float):
        return math.isfinite(v) and v.is_integer() and -MAX_SAFE <= v <= MAX_SAFE
    return False


def is_safe_uint(v) -> bool:
    return is_safe_int(v) and v >= 0


_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def b64decode_strict(s, expected_len: int | None = None, what: str = "value") -> bytes:
    if not isinstance(s, str) or s == "" or not _B64_RE.fullmatch(s):
        raise KernelError(C.B64_NONCANONICAL, f"{what} is not canonical base64")
    out = base64.b64decode(s, validate=True)
    if base64.b64encode(out).decode("ascii") != s:
        raise KernelError(C.B64_NONCANONICAL, f"{what} has non-zero padding bits")
    if expected_len is not None and len(out) != expected_len:
        code = C.KEY_SIZE if expected_len == 1952 else C.SIG_SIZE if expected_len == 3309 else C.INPUT_SHAPE
        raise KernelError(code, f"{what} is {len(out)} bytes, expected {expected_len}")
    return out


def is_hex(s, n: int | None = None) -> bool:
    if not isinstance(s, str):
        return False
    return re.fullmatch(r"[0-9a-f]+" if n is None else r"[0-9a-f]{%d}" % n, s) is not None


def is_hex0x(s, n: int) -> bool:
    return isinstance(s, str) and re.fullmatch(r"0x[0-9a-fA-F]{%d}" % n, s) is not None


def qty(h, what: str = "quantity") -> int:
    if not isinstance(h, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", h):
        raise KernelError(C.ANCHOR_LOG_MALFORMED, f"{what} is not a hex quantity")
    v = int(h[2:], 16)
    if v > MAX_SAFE:
        raise KernelError(C.ANCHOR_LOG_MALFORMED, f"{what} out of range")
    return v


def to_qty(n: int) -> str:
    return "0x" + format(n, "x")


_UNSAFE = re.compile("[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def one_line(s, maximum: int = 600) -> str:
    t = _UNSAFE.sub(lambda m: "\\u%04x" % ord(m.group(0)), str(s))
    return t[:maximum] + "…(truncated)" if len(t) > maximum else t


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.URLError(f"redirect refused ({code})")


def bounded_fetch(url: str, *, data: bytes | None = None, timeout: float = 20.0, max_bytes: int = 2 * 1024 * 1024) -> str:
    """HTTPS (or loopback http) request, no redirects, JSON content type, streamed byte cap. Raises KernelError."""
    if not (url.startswith("https://") or url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
        raise KernelError(C.RPC_ERROR, "refusing non-HTTPS URL")
    req = urllib.request.Request(url, data=data, headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "fractalai-trust-kernel-py/2"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as resp:  # noqa: S310
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype and not re.fullmatch(r"application/([a-z0-9.+-]*\+)?json", ctype):
                raise KernelError(C.RPC_ERROR, f"unexpected content-type {ctype!r}")
            body = resp.read(max_bytes + 1)
    except KernelError:
        raise
    except Exception as e:  # noqa: BLE001
        raise KernelError(C.RPC_ERROR, f"fetch failed: {one_line(e, 160)}") from None
    if len(body) > max_bytes:
        raise KernelError(C.JSON_TOO_LARGE, f"response larger than {max_bytes} bytes")
    return body.decode("utf-8", "replace")
