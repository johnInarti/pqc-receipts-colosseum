"""Top-level receipt verification.

Two receipt shapes are understood:

1. **Served receipts** as returned by ``/api/midas/alerts/receipt/<id>`` (fields ``receipt_id``,
   ``canonical``, ``served_message``, ``signature``, ``public_key``). Same checks as
   ``verifier/verify-midas-alert.mjs``:

   * ``receipt_id == sha256(canonical)``
   * ``served_message == "FRACTALAI-x402-served-v1\\n<route>\\n<receipt_id>"`` (route ``midas-alert`` by default)
   * ML-DSA-65 signature over ``served_message`` verifies
   * the signing key is in the trusted set (e.g. ``status == "active"`` in the key directory)

2. **Conformance-profile entries** (any object with a ``profile`` field from :data:`PROFILES`), checked by
   :func:`~fractalai_pqc_verify.profiles.verify_profile`.

Both are FAIL-CLOSED: ``valid`` is true only when the signature verifies AND the key is trusted.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from . import mldsa
from ._safe import https_get_json, strict_json_loads
from .directory import USER_AGENT
from .jcs import canonicalize
from .profiles import PROFILES, VerificationResult, normalize_trusted_keys, strict_b64, verify_profile

__all__ = ["SERVED_DOMAIN", "DEFAULT_BASE_URL", "verify_receipt", "fetch_midas_receipt"]

SERVED_DOMAIN = "FRACTALAI-x402-served-v1"
DEFAULT_BASE_URL = "https://fractalai.net.co"
_HEX64 = frozenset("0123456789abcdef")
_RESERVED_ROUTES = frozenset({"x402-attest-decision"})  # H3: owned by the acp-verdict profile
# Fields that only exist on a served receipt. A `profile` entry carrying any of them is ambiguous: the
# attacker-chosen `profile` would otherwise route a tampered served receipt around the served checks.
_SERVED_FIELDS = ("receipt_id", "canonical", "served_message", "facts", "snapshot")
_DEFAULT = object()


def _parse_canonical(canonical: str) -> tuple[str, dict[str, str]] | None:
    """``<domain>\nkey=value\n...`` -> (domain, {key: value}); None if it is not that shape."""
    lines = canonical.split("\n")
    out: dict[str, str] = {}
    for line in lines[1:]:
        if "=" not in line:
            return None
        k, v = line.split("=", 1)
        out[k] = v
    return lines[0], out


def _fmt(v: Any) -> str:
    # how JavaScript renders a value inside a template string (numbers: Number::toString == JSON form)
    if isinstance(v, str):
        return v
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    return canonicalize(v)


def _facts_mismatch(facts: Any, signed: dict[str, str]) -> list[str]:
    if not isinstance(facts, Mapping):
        return ["facts is not an object"]
    bad = []
    for k, v in signed.items():
        if k in facts:
            try:
                if _fmt(facts[k]) != v:
                    bad.append(k)
            except (TypeError, ValueError, RecursionError):
                bad.append(k)
    # red-team F2: a key the signer never signed must not ride along inside `facts`
    bad.extend(f"{k} (unsigned)" for k in facts if k not in signed)
    return bad


def _verify_served(receipt: Mapping[str, Any], trusted: frozenset[str] | None, expected_route: str | None, backend: str | None) -> VerificationResult:
    rid = receipt.get("receipt_id")
    canonical = receipt.get("canonical")
    served = receipt.get("served_message")
    pk_b64 = receipt.get("public_key")
    checks: dict[str, Any] = {}

    if not (isinstance(rid, str) and len(rid) == 64 and set(rid) <= _HEX64):
        return VerificationResult(False, False, False, "receipt_id is not a lowercase sha256 hex digest", "served", pk_b64, checks)
    checks["receipt_id_is_sha256_of_canonical"] = isinstance(canonical, str) and hashlib.sha256(canonical.encode("utf-8")).hexdigest() == rid

    # The signature binds `canonical`; the convenience `facts` object is NOT signed. Expose the signed
    # values and refuse a receipt whose `facts` contradict them (an agent would otherwise act on them).
    parsed = _parse_canonical(canonical) if isinstance(canonical, str) else None
    if parsed is not None:
        checks["signed_domain"], checks["signed_facts"] = parsed
    facts_ok = True
    bad: list[str] = []
    if "facts" in receipt and parsed is not None:
        bad += _facts_mismatch(receipt["facts"], parsed[1])
        checks["facts_match_canonical"] = not bad
    if parsed is not None:
        signed = parsed[1]
        # red-team F2: the top-level `emitted_at` copy is unsigned -- it must equal the signed value
        if "emitted_at" in receipt and "emitted_at" in signed:
            try:
                if _fmt(receipt["emitted_at"]) != signed["emitted_at"]:
                    bad.append("emitted_at (top-level)")
            except (TypeError, ValueError, RecursionError):
                bad.append("emitted_at (top-level)")
        # red-team F2: `snapshot` is committed by the SIGNED snapshot_hash = sha256(JCS(snapshot))
        if "snapshot" in receipt:
            try:
                snap_ok = "snapshot_hash" in signed and hashlib.sha256(canonicalize(receipt["snapshot"]).encode("utf-8")).hexdigest() == signed["snapshot_hash"]
            except (TypeError, ValueError, RecursionError):
                snap_ok = False
            checks["snapshot_matches_signed_hash"] = snap_ok
            if not snap_ok:
                bad.append("snapshot (sha256(JCS(snapshot)) != signed snapshot_hash)")
    elif any(k in receipt for k in ("facts", "snapshot")):
        bad.append("facts/snapshot present but canonical is not parseable")
    if bad:
        facts_ok = False
        checks["facts_mismatch"] = bad

    route = expected_route
    if route is None and isinstance(served, str) and served.startswith(SERVED_DOMAIN + "\n"):
        parts = served.split("\n")
        route = parts[1] if len(parts) == 3 else None
    checks["route"] = route
    checks["domain_string_matches"] = route is not None and route not in _RESERVED_ROUTES and served == f"{SERVED_DOMAIN}\n{route}\n{rid}"

    try:
        sig, pk = strict_b64(receipt.get("signature")), strict_b64(pk_b64)
        sig_ok = isinstance(served, str) and mldsa.verify(pk, served.encode("utf-8"), sig, backend=backend)
    except ValueError as e:
        sig_ok = False
        checks["encoding_error"] = str(e)
    except Exception as e:  # backend selection/import problems are a rejection, never a crash (F9b)
        sig_ok = False
        checks["backend_error"] = f"{type(e).__name__}: {e}"
    checks["ml_dsa65_signature_valid"] = sig_ok

    key_trusted = trusted is not None and isinstance(pk_b64, str) and pk_b64 in trusted
    checks["key_trusted"] = key_trusted

    signature_valid = bool(checks["receipt_id_is_sha256_of_canonical"] and checks["domain_string_matches"] and sig_ok)
    if not checks["receipt_id_is_sha256_of_canonical"]:
        reason = "receipt_id != sha256(canonical) — facts tampered"
    elif not facts_ok:
        signature_valid = False
        reason = f"unsigned fields contradict or extend the signed canonical text ({', '.join(checks['facts_mismatch'])}) — tampered"
    elif not checks["domain_string_matches"]:
        reason = f"served_message != '{SERVED_DOMAIN}\\n{route}\\n<receipt_id>' — wrong domain/route"
    elif not sig_ok:
        reason = "ML-DSA-65 signature INVALID"
    elif trusted is None:
        reason = "signature verifies, but no trusted_keys supplied — authorship UNVERIFIED"
    elif not key_trusted:
        reason = "signature verifies, but the signing key is NOT in the trusted set — untrusted key"
    else:
        reason = f"authentic: ML-DSA-65 signature by a trusted key over the served proof ({route})"
    return VerificationResult(signature_valid and key_trusted, signature_valid, key_trusted, reason, "served", pk_b64, checks)


def verify_receipt(
    receipt: Mapping[str, Any] | str,
    trusted_keys: Any = None,
    *,
    expected_route: Any = _DEFAULT,
    expected_profile: str | None = None,
    backend: str | None = None,
) -> VerificationResult:
    """Verify a FractalAI post-quantum receipt OFFLINE.

    :param receipt: the receipt as a dict, or its JSON text.
    :param trusted_keys: iterable of base64 ML-DSA-65 public keys, a single key string, or a
        :class:`~fractalai_pqc_verify.directory.KeyDirectory` (its ``active`` keys are used). ``None`` means
        "no trust anchor" and always yields ``valid=False``.
    :param expected_route: the route the signature must be bound to. For served receipts the default is
        ``"midas-alert"`` (``None`` accepts whatever route the receipt names and reports it). For an
        ``x402-served`` profile entry it is enforced only when passed explicitly.
    :param expected_profile: ``"served"`` or one of :data:`PROFILES`. When given, a receipt of any other
        kind is refused -- use it whenever you know what you expect (e.g. ``"served"`` for MIDAS alerts),
        so a genuine signature of another kind by the same trusted key cannot be substituted.
    :returns: :class:`VerificationResult` -- truthy only if authentic. Never raises on hostile input.
    """
    try:
        return _verify_receipt(receipt, trusted_keys, expected_route, expected_profile, backend)
    except Exception as e:  # red-team F7/F9b: hostile input is a rejection, never a crash
        return VerificationResult(False, False, False, f"verify error: {type(e).__name__}: {e}")


def _verify_receipt(receipt, trusted_keys, expected_route, expected_profile, backend) -> VerificationResult:
    if isinstance(receipt, (str, bytes)):
        try:
            receipt = strict_json_loads(receipt)
        except ValueError as e:
            return VerificationResult(False, False, False, f"receipt is not valid JSON: {e}")
    if not isinstance(receipt, Mapping):
        return VerificationResult(False, False, False, "receipt must be a JSON object")
    trusted = normalize_trusted_keys(trusted_keys)
    profile = receipt.get("profile")
    if profile is not None and any(k in receipt for k in _SERVED_FIELDS):
        # red-team F1: the attacker picks `profile`; a served receipt must never be re-routed to a
        # profile checker that ignores receipt_id/canonical/facts.
        return VerificationResult(False, False, False, f"ambiguous receipt: `profile`={profile!r} together with served-receipt fields — refuse", None)
    if isinstance(profile, str) and profile in PROFILES:
        if expected_profile is not None and expected_profile != profile:
            return VerificationResult(False, False, False, f"expected a {expected_profile!r} receipt, got profile {profile!r}", profile)
        if profile == "x402-served" and expected_route is not _DEFAULT and expected_route is not None and receipt.get("route_id") != expected_route:
            return VerificationResult(False, False, False, f"route_id {receipt.get('route_id')!r} != expected route {expected_route!r}", profile)
        return verify_profile(profile, receipt, trusted, backend=backend)
    if "served_message" in receipt or "canonical" in receipt:
        if expected_profile is not None and expected_profile != "served":
            return VerificationResult(False, False, False, f"expected a {expected_profile!r} receipt, got a served receipt", "served")
        route = "midas-alert" if expected_route is _DEFAULT else expected_route
        return _verify_served(receipt, trusted, route, backend)
    return VerificationResult(False, False, False, f"unknown receipt shape (profile={profile!r})")


def fetch_midas_receipt(receipt_id: str, base_url: str = DEFAULT_BASE_URL, *, timeout: float = 15.0) -> dict[str, Any]:
    """Download a public MIDAS signed-alert receipt (network). Verification is still done offline."""
    if not (len(receipt_id) == 64 and set(receipt_id.lower()) <= _HEX64):
        raise ValueError("receipt_id must be 64 hex chars")
    if not base_url.startswith("https://"):
        raise ValueError("refusing non-HTTPS base URL")
    # red-team F6: no redirect may leave https://, body size capped, JSON content type, strict JSON
    data, _ = https_get_json(f"{base_url.rstrip('/')}/api/midas/alerts/receipt/{receipt_id.lower()}", user_agent=USER_AGENT, timeout=timeout)
    if not isinstance(data, dict):
        raise ValueError("receipt endpoint did not return a JSON object")
    return data
