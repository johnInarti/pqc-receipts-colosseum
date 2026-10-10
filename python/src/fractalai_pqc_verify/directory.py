"""Epoch-chained, ML-DSA-65-signed key directory (``/.well-known/x402-receipt-keys``), ported from
``conformance/src/key-directory.mjs``.

The directory is itself a verifiable object: (1) signed with ML-DSA-65 by a governance key over
``FRACTALAI-key-directory-v1\\n<root>``, (2) append-only and chained (each epoch commits to ``prev_root``),
(3) anchorable (``root`` is what goes on-chain). :func:`verify_directory` checks all of that offline.

Honest scope: a directory that verifies against its OWN embedded governance key proves integrity, not
authorship. Authenticity needs a pinned ``governance_key`` or an on-chain ``anchored_root``. Without one,
:func:`fetch_key_directory` still rejects any tampered directory, but the trust basis is your TLS
connection to the issuer (``KeyDirectory.trust_basis == "tls"``) -- pin the governance key after the first
run if you do not want to trust TLS.
"""
from __future__ import annotations

import copy
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urljoin

from . import mldsa
from ._safe import https_get_json, strict_json_loads
from .jcs import canonicalize
from .profiles import strict_b64

__all__ = [
    "DEFAULT_DIRECTORY_URL",
    "LEGACY_DIRECTORY_PATH",
    "LEGACY_DIRECTORY_SPEC",
    "KEY_DIR_DOMAIN",
    "DirectoryVerification",
    "KeyDirectory",
    "KeyDirectoryError",
    "directory_root",
    "fetch_key_directory",
    "kid_for_key",
    "load_key_directory",
    "verify_directory",
]

DEFAULT_DIRECTORY_URL = "https://fractalai.net.co/.well-known/x402-receipt-keys"
#: The x402 delivery-receipt spec (§7.1) reserves /.well-known/x402-receipt-keys for its own format
#: (x402-receipt-key-directory/1). FractalAI's FRACTALAI-key-directory-v1 chain moves, byte for byte, to
#: LEGACY_DIRECTORY_PATH; signed receipts that embed the old URL keep verifying through the same-origin
#: relocation in fetch_key_directory (a document's own pointers are never followed).
LEGACY_DIRECTORY_SPEC = "FRACTALAI-key-directory-v1"
LEGACY_DIRECTORY_PATH = "/.well-known/fractalai-key-directory"
KEY_DIR_DOMAIN = "FRACTALAI-key-directory-v1"
_ZERO_ROOT = "0" * 64
USER_AGENT = "fractalai-pqc-verify (+https://github.com/johnInarti/pqc-receipts-colosseum)"


class KeyDirectoryError(ValueError):
    """The directory failed verification (tampered, wrong signer, discontinuous chain, ...)."""


def _sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def kid_for_key(public_key_b64: str) -> str:
    """``kid`` MUST equal ``sha256(public_key_b64)[:16]`` so a label cannot alias another key."""
    return _sha256hex(public_key_b64)[:16]


def directory_root(keys: Iterable[Mapping[str, Any]], prev_root: str | None, epoch: Any, governance_key_b64: str | None) -> str:
    """Canonical root over the epoch: full key objects (sorted by kid), governance signer and chain."""
    canonical_keys = sorted(keys, key=lambda k: k["kid"])
    return _sha256hex(
        canonicalize({"epoch": epoch, "prev_root": prev_root or _ZERO_ROOT, "governance_key": governance_key_b64 or None, "keys": canonical_keys})
    )


@dataclass(frozen=True)
class DirectoryVerification:
    valid: bool
    signature_valid: bool
    reason: str


def verify_directory(
    directory: Mapping[str, Any],
    *,
    governance_key: str | None = None,
    anchored_root: str | None = None,
    expected_prev_root: str | None = None,
    backend: str | None = None,
) -> DirectoryVerification:
    """Verify a directory epoch OFFLINE, FAIL-CLOSED (same rules as ``verifyDirectory`` in Node).

    ``valid`` is true only if signature, root and kid bindings hold AND the signer is pinned
    (``governance_key``) or the root matches ``anchored_root``. ``signature_valid`` reports integrity alone.
    """

    def no(reason: str, signature_valid: bool = False) -> DirectoryVerification:
        return DirectoryVerification(False, signature_valid, reason)

    try:
        if directory.get("spec") != KEY_DIR_DOMAIN:
            return no(f"not a {KEY_DIR_DOMAIN} directory")
        pk = strict_b64(directory.get("directory_public_key"))
        sig = strict_b64(directory.get("signature"))
        if len(pk) != mldsa.PUBLIC_KEY_BYTES:
            return no("governance public key is not 1952 bytes (not ML-DSA-65)")
        if len(sig) != mldsa.SIGNATURE_BYTES:
            return no("governance signature is not 3309 bytes (not ML-DSA-65)")
        keys = directory.get("keys")
        if not isinstance(keys, list):  # red-team F11: parity with Node (null/""/0 is not an empty key set)
            return no("directory keys is not a list")
        for k in keys:
            if k.get("kid") != kid_for_key(k.get("public_key_b64")):
                return no(f"kid {k.get('kid')} != sha256(public_key)[:16] — forged/aliased kid")
        recomputed = directory_root(keys, directory.get("prev_root"), directory.get("epoch"), directory["directory_public_key"])
        if recomputed != directory.get("root"):
            return no("directory root != recomputed root (keys/governance/chain) — tampered")
        if directory.get("signed_message") != f"{KEY_DIR_DOMAIN}\n{directory['root']}":
            return no("signed_message != domain\\nroot — non-canonical")
        if not mldsa.verify(pk, directory["signed_message"].encode("utf-8"), sig, backend=backend):
            return no("governance signature does not verify")
        if governance_key and governance_key != directory["directory_public_key"]:
            return no("directory signer != pinned governance key — untrusted directory", True)
        if anchored_root and anchored_root.lower() != directory["root"].lower():
            return no("directory root != on-chain anchored root — possible equivocation, refuse", True)
        if expected_prev_root and (directory.get("prev_root") or _ZERO_ROOT).lower() != expected_prev_root.lower():
            return no("prev_root does not chain to the expected previous epoch — discontinuity", True)
        if not governance_key and not anchored_root:
            return no(
                "directory signature verifies but the signer is UNVERIFIED — supply a pinned governance_key "
                "or an anchored_root (a self-signed directory is not trust)",
                True,
            )
        basis = "pinned governance key" if governance_key else "signer whose root matches the on-chain anchor"
        return DirectoryVerification(True, True, f"authentic: ML-DSA-65-signed directory by a {basis}; root recomputes")
    except Exception as e:  # malformed input is a rejection, never a crash
        return no(f"verify error: {e}")


_UNPARSABLE = object()


def _as_int(v: Any) -> Any:
    """None/"None"/"" -> None (no expiry); an int or decimal-int string -> int; anything else -> _UNPARSABLE."""
    if v is None or v == "None" or v == "":
        return None
    if isinstance(v, bool):
        return _UNPARSABLE
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().lstrip("-").isdigit():
        return int(v)
    return _UNPARSABLE


@dataclass(frozen=True)
class KeyDirectory:
    """A directory whose signature, root and kid bindings have been verified."""

    raw: Mapping[str, Any]
    source: str
    trust_basis: str  # "pinned-governance-key" | "anchored-root" | "tls" | "local-file"
    verification: DirectoryVerification
    fetched_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def epoch(self) -> Any:
        return self.raw.get("epoch")

    @property
    def root(self) -> str:
        return self.raw["root"]

    @property
    def governance_key(self) -> str:
        return self.raw["directory_public_key"]

    @property
    def keys(self) -> list[Mapping[str, Any]]:
        return list(self.raw.get("keys") or [])

    def status_of(self, public_key_b64: str) -> str:
        for k in self.keys:
            if k.get("public_key_b64") == public_key_b64:
                return str(k.get("status"))
        return "NOT_FOUND"

    def trusted_keys(self, *, include_retiring: bool = False, now: int | None = None) -> list[str]:
        """Keys a receipt may be signed by. Default: only ``status == "active"`` (exactly what the reference
        Node verifier requires). ``include_retiring=True`` also accepts ``retiring`` keys until their
        ``not_after`` -- pass the receipt's ``emitted_at`` as ``now`` to apply the rule "signed while the key
        was still valid" (default ``now`` = current time). ``reserved`` and ``revoked`` keys are never trusted."""
        now = int(time.time()) if now is None else now
        out = []
        for k in self.keys:
            status = k.get("status")
            if status == "active":
                out.append(k["public_key_b64"])
            elif include_retiring and status == "retiring":
                not_after = _as_int(k.get("not_after"))
                if not_after is _UNPARSABLE:  # red-team F8b: garbage expiry is fail-closed, not "never"
                    continue
                if not_after is None or now <= not_after:
                    out.append(k["public_key_b64"])
        return out


def _check(
    raw: Mapping[str, Any],
    source: str,
    *,
    governance_key: str | None,
    anchored_root: str | None,
    expected_prev_root: str | None,
    require_authenticated: bool,
    default_basis: str,
    backend: str | None,
) -> KeyDirectory:
    raw = copy.deepcopy(dict(raw))  # red-team F10: freeze what was verified (no TOCTOU via the caller's dict)
    v = verify_directory(raw, governance_key=governance_key, anchored_root=anchored_root, expected_prev_root=expected_prev_root, backend=backend)
    if not v.signature_valid:
        raise KeyDirectoryError(f"key directory rejected: {v.reason}")
    if not v.valid and (governance_key or anchored_root or expected_prev_root):
        raise KeyDirectoryError(f"key directory rejected: {v.reason}")
    if not v.valid and require_authenticated:
        raise KeyDirectoryError(f"key directory not authenticated: {v.reason}")
    basis = "pinned-governance-key" if governance_key else "anchored-root" if anchored_root else default_basis
    return KeyDirectory(raw=raw, source=source, trust_basis=basis, verification=v)


def fetch_key_directory(
    url: str = DEFAULT_DIRECTORY_URL,
    *,
    governance_key: str | None = None,
    anchored_root: str | None = None,
    expected_prev_root: str | None = None,
    require_authenticated: bool = False,
    timeout: float = 15.0,
    backend: str | None = None,
) -> KeyDirectory:
    """Download the key directory over HTTPS and verify it (signature, root recomputation, kid binding).

    Always raises :class:`KeyDirectoryError` on a tampered directory. If ``governance_key`` /
    ``anchored_root`` / ``expected_prev_root`` are given they must match. With none of them the result's
    ``trust_basis`` is ``"tls"``; pass ``require_authenticated=True`` to refuse that.
    """
    if not url.startswith("https://"):
        raise KeyDirectoryError("refusing non-HTTPS key directory URL")
    # red-team F6: no https->http redirect (the "tls" trust basis would be a lie), size cap, JSON only
    try:
        raw, final_url = https_get_json(url, user_agent=USER_AGENT, timeout=timeout)
    except (ValueError, OSError) as e:
        raw, final_url, first_error = None, url, e
    else:
        first_error = None
    if not (isinstance(raw, dict) and raw.get("spec") == LEGACY_DIRECTORY_SPEC):
        alt = urljoin(url, LEGACY_DIRECTORY_PATH)
        if alt == url:
            if first_error is not None:
                raise KeyDirectoryError(f"key directory fetch refused: {first_error}") from first_error
            raise KeyDirectoryError(f"{url} is not a {LEGACY_DIRECTORY_SPEC} document")
        try:
            raw, final_url = https_get_json(alt, user_agent=USER_AGENT, timeout=timeout)
        except (ValueError, OSError) as e:
            raise KeyDirectoryError(f"key directory fetch refused at {url} and {alt}: {e}") from e
        if not (isinstance(raw, dict) and raw.get("spec") == LEGACY_DIRECTORY_SPEC):
            raise KeyDirectoryError(f"neither {url} nor {alt} is a {LEGACY_DIRECTORY_SPEC} document")
    return _check(
        raw, final_url, governance_key=governance_key, anchored_root=anchored_root, expected_prev_root=expected_prev_root,
        require_authenticated=require_authenticated, default_basis="tls", backend=backend,
    )


def load_key_directory(
    source: str | Path | Mapping[str, Any],
    *,
    governance_key: str | None = None,
    anchored_root: str | None = None,
    expected_prev_root: str | None = None,
    require_authenticated: bool = False,
    backend: str | None = None,
) -> KeyDirectory:
    """Same as :func:`fetch_key_directory` but from a saved JSON file or an already-parsed dict (offline)."""
    if isinstance(source, Mapping):
        raw, name = source, "<dict>"
    else:
        try:
            raw, name = strict_json_loads(Path(source).read_text("utf-8")), str(source)
        except ValueError as e:
            raise KeyDirectoryError(f"key directory is not valid JSON: {e}") from e
        if not isinstance(raw, dict):
            raise KeyDirectoryError("key directory is not a JSON object")
    return _check(
        raw, name, governance_key=governance_key, anchored_root=anchored_root, expected_prev_root=expected_prev_root,
        require_authenticated=require_authenticated, default_basis="local-file", backend=backend,
    )
