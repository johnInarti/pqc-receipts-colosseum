"""Kind ``agent-commerce-receipt`` — Python mirror of kernel/src/commerce.mjs (spec/TRUST-KERNEL.md §13).
Same closed body shape, same signed message, same reason codes. The kernel never interprets ``payment`` or
``bindings``: their meaning is defined by the profile (adapters outside the kernel)."""
from __future__ import annotations

import re

from ..jcs import canonicalize
from ._codes import C, fail
from ._crypto import ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES, sha256hex
from ._hygiene import b64decode_strict, is_hex, is_safe_int, own

COMMERCE_DOMAIN = "FRACTALAI-agent-commerce-receipt-v1"
COMMERCE_VERSION = "fractalai.agent-commerce/1"
COMMERCE_USE = "commerce-receipt"
COMMERCE_MAX_BYTES = 8192
MARKERS = ["commerce", "commerce_id"]

_PROTOCOL = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_PROFILE = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}/[1-9][0-9]{0,5}")
_ENTRY_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ENTRY_VALUE = re.compile(r"[\x20-\x7e]{1,512}")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")
_BODY_KEYS = sorted(["bindings", "delivery", "issued_at", "payment", "profile", "protocol", "v"])
_DELIVERY_KEYS = {"sha256", "media_type", "size"}


def _bad(detail):
    fail(C.COMMERCE_MALFORMED, detail)


def _entries(obj, what, mx):
    if not isinstance(obj, dict):
        _bad(f"{what} is not an object")
    if len(obj) > mx:
        _bad(f"{what} has more than {mx} entries")
    for k, val in obj.items():
        if not _ENTRY_KEY.fullmatch(k):
            _bad(f"{what} key {k[:40]!r} does not match ^[a-z][a-z0-9_]{{0,63}}$")
        if not isinstance(val, str) or not _ENTRY_VALUE.fullmatch(val):
            _bad(f"{what}.{k} must be 1..512 printable ASCII characters")


def check_commerce_body(b) -> int:
    """Strict shape of the signed body (spec §13.2). Returns the signed time."""
    if not isinstance(b, dict):
        _bad("commerce is not an object")
    if sorted(b.keys()) != _BODY_KEYS:
        _bad(f"commerce must have exactly the keys {', '.join(_BODY_KEYS)}")
    if b["v"] != COMMERCE_VERSION:
        _bad(f"commerce.v is not {COMMERCE_VERSION}")
    if not isinstance(b["protocol"], str) or not _PROTOCOL.fullmatch(b["protocol"]):
        _bad("commerce.protocol must match ^[a-z0-9][a-z0-9-]{0,31}$")
    if not isinstance(b["profile"], str) or not _PROFILE.fullmatch(b["profile"]):
        _bad("commerce.profile must match <name>/<version>")
    if not is_safe_int(b["issued_at"]) or b["issued_at"] < 1:
        _bad("commerce.issued_at must be a positive safe integer (unix seconds)")
    _entries(b["payment"], "payment", 16)
    _entries(b["bindings"], "bindings", 16)
    d = b["delivery"]
    if not isinstance(d, dict):
        _bad("delivery is not an object")
    for k in d:
        if k not in _DELIVERY_KEYS:
            _bad(f"delivery has an unknown key {k[:40]!r}")
    if not is_hex(d.get("sha256"), 64):
        _bad("delivery.sha256 must be 64 lowercase hex")
    if "media_type" in d and (not isinstance(d["media_type"], str) or not _MEDIA_TYPE.fullmatch(d["media_type"])):
        _bad("delivery.media_type is not a lowercase type/subtype")
    if "size" in d and (not is_safe_int(d["size"]) or d["size"] < 0):
        _bad("delivery.size must be a non-negative safe integer")
    return int(b["issued_at"])


def parse_commerce_receipt(r, ctx=None):
    known = {"commerce", "commerce_id", "public_key", "signature", "algorithm", "domain", "signed_message", "issued_at", "profile"}
    if own(r, "algorithm") and r["algorithm"] != "ml-dsa-65":
        fail(C.ALGORITHM, f"algorithm {r['algorithm']!r} is not ml-dsa-65")
    if "commerce" not in r:
        fail(C.INPUT_SHAPE, "agent-commerce-receipt needs a commerce object")
    signed_time = check_commerce_body(r["commerce"])
    # The body holds only ASCII strings and safe integers (checked above), the subset every runtime
    # canonicalises identically; a float like 5.0 is rendered as 5 by the shared JCS implementation.
    canonical = canonicalize(r["commerce"])
    if len(canonical.encode("utf-8")) > COMMERCE_MAX_BYTES:
        _bad(f"JCS(commerce) exceeds {COMMERCE_MAX_BYTES} bytes")
    cid = sha256hex(canonical)
    message = f"{COMMERCE_DOMAIN}\n{cid}"
    if own(r, "commerce_id") and r["commerce_id"] != cid:
        fail(C.RECEIPT_ID_MISMATCH, "commerce_id != sha256(JCS(commerce))")
    if own(r, "domain") and r["domain"] != COMMERCE_DOMAIN:
        fail(C.DOMAIN_MISMATCH, f"domain is not {COMMERCE_DOMAIN}")
    if own(r, "signed_message") and r["signed_message"] != message:
        fail(C.SIGNED_MESSAGE_MISMATCH, "signed_message != reconstructed signed message")
    if own(r, "issued_at") and (not is_safe_int(r["issued_at"]) or r["issued_at"] != signed_time):
        fail(C.UNSIGNED_FIELD_MISMATCH, f"top-level issued_at {r['issued_at']!r} != signed issued_at {signed_time}")
    return {
        "kind": "agent-commerce-receipt", "content_id": cid, "message": message,
        "pk": b64decode_strict(r.get("public_key"), ML_DSA_65_PK_BYTES, "public_key"),
        "sig": b64decode_strict(r.get("signature"), ML_DSA_65_SIG_BYTES, "signature"),
        "public_key_b64": r.get("public_key"), "signed_time": signed_time,
        "signed": {"commerce_id": cid, **r["commerce"]},
        "ignored": [k for k in r if k not in known and k not in ("anchor", "anchors")],
    }
