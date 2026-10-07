"""The 7 PQC agent-receipt profiles of the conformance suite, ported 1:1 from ``conformance/src/profiles.mjs``.

TRUST MODEL (fail-closed): a signature that verifies proves only that SOME key signed these bytes. ``valid``
is true only when the ML-DSA-65 signature verifies AND the embedded public key is in the caller-supplied
``trusted_keys``. With ``trusted_keys=None`` the result is ``valid=False`` (authorship unverified) even for a
genuine receipt -- a self-signed forgery never gets a green check.

Honest scope: attests authorship + integrity of the bytes (non-repudiation), not that the underlying
action/content is correct; uses the FIPS 204 algorithm through an open-source library, not a CMVP module.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from . import mldsa
from ._safe import strict_json_loads
from .jcs import canonicalize

__all__ = ["PROFILES", "VerificationResult", "normalize_trusted_keys", "verify_profile"]

_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    signature_valid: bool
    key_trusted: bool
    reason: str
    profile: str | None = None
    public_key: str | None = None
    checks: Mapping[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:  # `if verify_receipt(...)` means "authentic", never just "signature ok"
        return self.valid

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signature_valid": self.signature_valid,
            "key_trusted": self.key_trusted,
            "reason": self.reason,
            "profile": self.profile,
            "public_key": self.public_key,
            "checks": dict(self.checks),
        }


class _Fail(Exception):
    pass


def strict_b64(s: Any) -> bytes:
    """Canonical standard base64 only (no whitespace, right alphabet, length % 4 == 0)."""
    # fullmatch, not match: `$` also matches before a trailing "\n" (red-team F3)
    if not isinstance(s, str) or len(s) % 4 != 0 or not _B64.fullmatch(s):
        raise ValueError("non-canonical base64")
    return base64.b64decode(s, validate=True)


def strict_b64url(s: Any) -> bytes:
    if not isinstance(s, str) or not _B64URL.fullmatch(s):
        raise ValueError("non-canonical base64url")
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    try:
        # validate=True: never silently drop characters outside the alphabet (red-team F3)
        return base64.b64decode((s + pad).replace("-", "+").replace("_", "/"), validate=True)
    except binascii.Error as e:
        raise ValueError(f"bad base64url: {e}") from e


def _sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _size_error(sig: bytes, pk: bytes) -> str | None:
    if len(pk) != mldsa.PUBLIC_KEY_BYTES:
        return f"public key is {len(pk)} bytes, not {mldsa.PUBLIC_KEY_BYTES} (not ML-DSA-65)"
    if len(sig) != mldsa.SIGNATURE_BYTES:
        return f"signature is {len(sig)} bytes, not {mldsa.SIGNATURE_BYTES} (not ML-DSA-65)"
    return None


def _ok(sig: bytes, msg: bytes, pk: bytes, pk_b64: str, reason: str, backend: str | None):
    return {"signature_valid": mldsa.verify(pk, msg, sig, backend=backend), "public_key": pk_b64, "reason": reason}


def _no(reason: str):
    return {"signature_valid": False, "reason": reason}


def _without(d: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in keys}


def _x402_served(e, backend):
    # H3: the reserved acp-verdict route must not be accepted by the generic profile (one sig = one meaning).
    if e.get("route_id") == "x402-attest-decision":
        return _no("route 'x402-attest-decision' is reserved for the acp-verdict profile — refuse cross-profile use")
    sig, pk = strict_b64(e.get("signature")), strict_b64(e.get("public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    expected = f"{e.get('domain')}\n{e.get('route_id')}\n{e.get('digest')}"
    if not all(isinstance(e.get(k), str) for k in ("domain", "route_id", "digest")) or e.get("signed_message") != expected:
        return _no("signed_message != domain\\nroute\\ndigest (non-canonical)")
    return _ok(sig, expected.encode(), pk, e["public_key"], "x402-served", backend)


def _sar(e, backend):
    sig, pk = strict_b64(e.get("signature")), strict_b64(e.get("public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    core = _without(e.get("sar") or {}, "signatures")
    expected = f"x402-sar-pqc-v1\n{_sha256hex(canonicalize(core))}"
    if e.get("signed_message") != expected:
        return _no("signed_message != x402-sar-pqc-v1\\nsha256(JCS(core)) — tampered/non-canonical")
    return _ok(sig, expected.encode(), pk, e["public_key"], "sar", backend)


def _acp_verdict(e, backend):
    sig, pk = strict_b64(e.get("signature")), strict_b64(e.get("public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    if "decision" not in e:
        return _no("no decision object")
    expected = f"FRACTALAI-x402-served-v1\nx402-attest-decision\n{_sha256hex(canonicalize(e['decision']))}"
    if e.get("signed_message") != expected:
        return _no("signed_message != served proof over sha256(JCS(decision))")
    return _ok(sig, expected.encode(), pk, e["public_key"], "acp-verdict", backend)


def _vc_di(e, backend):
    doc = e.get("securedDocument")
    if not isinstance(doc, dict) or not doc.get("proof"):
        return _no("no DataIntegrityProof on the credential")
    proof = doc["proof"]
    unsecured = _without(doc, "proof")
    if proof.get("type") != "DataIntegrityProof":
        return _no(f"proof.type is '{proof.get('type')}', expected DataIntegrityProof")
    if proof.get("cryptosuite") != "mldsa65-jcs-2024":
        return _no(f"cryptosuite is '{proof.get('cryptosuite')}', expected mldsa65-jcs-2024")
    proof_value = proof.get("proofValue")
    proof_config = _without(proof, "proofValue")
    if not isinstance(proof_value, str) or not proof_value.startswith("u"):
        return _no("proofValue must be multibase base64url (u-prefixed)")
    sig, pk = strict_b64url(proof_value[1:]), strict_b64(e.get("public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    hash_data = (
        hashlib.sha256(canonicalize(proof_config).encode()).digest()
        + hashlib.sha256(canonicalize(unsecured).encode()).digest()
    )
    return _ok(sig, hash_data, pk, e["public_key"], "vc-di", backend)


def _jose(e, backend):
    parts = str(e.get("jws")).split(".")
    if len(parts) != 3:
        return _no("not a compact JWS (need 3 dot-separated parts)")
    h, p, s = parts
    try:
        header = strict_json_loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)).decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError
    except Exception:
        return _no("bad JWS header")
    if header.get("alg") != "ML-DSA-65":
        return _no(f"JOSE alg is '{header.get('alg')}', expected 'ML-DSA-65' (RFC 9964)")
    sig, pk = strict_b64url(s), strict_b64(e.get("public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    return _ok(sig, f"{h}.{p}".encode(), pk, e["public_key"], "jose", backend)


def _hai(e, backend):
    identity = e.get("identity") or {}
    if identity.get("format") != "eat+cwt+ml-dsa-65":
        return _no(f"identity.format is '{identity.get('format')}', expected 'eat+cwt+ml-dsa-65'")
    pqc = identity.get("pqc") or {}
    if pqc.get("algorithm") != "ml-dsa-65":
        return _no(f"identity.pqc.algorithm is '{pqc.get('algorithm')}', expected 'ml-dsa-65'")
    sig, pk = strict_b64(pqc.get("signature")), strict_b64(pqc.get("public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    core = {"publicKey": identity["publicKey"], "timestamp": identity["timestamp"], "nonce": identity["nonce"]}
    expected = f"FRACTALAI-hai-pqc-v1\n{_sha256hex(canonicalize(core))}"
    if pqc.get("signed_message") != expected:
        return _no("signed_message != FRACTALAI-hai-pqc-v1\\nsha256(JCS({publicKey,timestamp,nonce})) — tampered/non-canonical")
    return _ok(sig, expected.encode(), pk, pqc["public_key"], "hai", backend)


def _a2a(e, backend):
    receipt = e.get("receipt")
    if not isinstance(receipt, dict):
        return _no("no receipt object")
    if receipt.get("schema") != "a2a.signed-receipt/0.1":
        return _no(f"schema is '{receipt.get('schema')}', expected 'a2a.signed-receipt/0.1'")
    signature = receipt.get("signature")
    body = _without(receipt, "signature")
    if not isinstance(signature, dict) or signature.get("alg") != "ML-DSA-65":
        alg = signature.get("alg") if isinstance(signature, dict) else None
        return _no(f"signature.alg is '{alg}', expected 'ML-DSA-65'")
    sig, pk = strict_b64(signature.get("sig")), strict_b64(signature.get("signer_public_key"))
    if (sz := _size_error(sig, pk)):
        return _no(sz)
    content_id = body.get("content_id")
    unsigned = _without(body, "content_id")
    if not isinstance(content_id, str) or content_id != _sha256hex(canonicalize(unsigned)):
        return _no("content_id != sha256(JCS(receipt minus content_id/signature)) — tampered/non-canonical")
    return _ok(sig, canonicalize(body).encode(), pk, signature["signer_public_key"], "a2a-signed-receipt", backend)


_CHECKERS: dict[str, Callable[[Mapping[str, Any], str | None], dict]] = {
    "x402-served": _x402_served,
    "sar": _sar,
    "acp-verdict": _acp_verdict,
    "vc-di-ml-dsa-65": _vc_di,
    "jose-ml-dsa-65": _jose,
    "hai-ml-dsa-65": _hai,
    "a2a-receipt-ml-dsa-65": _a2a,
}

PROFILES: tuple[str, ...] = tuple(_CHECKERS)


def normalize_trusted_keys(trusted_keys: Any) -> frozenset[str] | None:
    """``None`` stays ``None`` (no trust anchor); a bare string is ONE key (not an iterable of chars);
    an object exposing ``trusted_keys()`` (e.g. :class:`~fractalai_pqc_verify.directory.KeyDirectory`)
    contributes its trusted set."""
    if trusted_keys is None:
        return None
    if isinstance(trusted_keys, str):
        return frozenset([trusted_keys])
    if hasattr(trusted_keys, "trusted_keys") and callable(trusted_keys.trusted_keys):
        return frozenset(trusted_keys.trusted_keys())
    return frozenset(k for k in trusted_keys if isinstance(k, str))


def verify_profile(
    profile: str,
    entry: Mapping[str, Any],
    trusted_keys: Iterable[str] | None = None,
    *,
    backend: str | None = None,
) -> VerificationResult:
    """Verify one receipt against its profile, FAIL-CLOSED on key provenance.

    ``trusted_keys``: base64 ML-DSA-65 public keys that count as authentic. ``None`` -> authorship
    unverified (``valid=False``); an empty list -> every key is untrusted.
    """
    checker = _CHECKERS.get(profile)
    if checker is None:
        return VerificationResult(False, False, False, f"unknown profile '{profile}'", profile)
    try:
        r = checker(entry, backend)
    except Exception as e:  # malformed input is a rejection, never a crash
        return VerificationResult(False, False, False, f"verify error: {e}", profile)
    signature_valid = r.get("signature_valid") is True
    trusted = normalize_trusted_keys(trusted_keys)
    pk = r.get("public_key")
    key_trusted = signature_valid and trusted is not None and bool(pk) and pk in trusted
    if not signature_valid:
        reason = f"signature INVALID ({r.get('reason')})"
    elif trusted is None:
        reason = "signature verifies over the bytes, but no trusted_keys supplied — authorship UNVERIFIED (a self-signed forgery reaches here)"
    elif not key_trusted:
        reason = "signature verifies, but the signing key is NOT in the trusted set — untrusted key (likely forgery)"
    else:
        reason = f"authentic: ML-DSA-65 signature by a trusted key over the exact {profile} bytes"
    return VerificationResult(signature_valid and key_trusted, signature_valid, key_trusted, reason, profile, pk)
