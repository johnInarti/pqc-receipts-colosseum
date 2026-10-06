"""ML-DSA-65 (FIPS 204, pure mode, empty context) signature verification backends.

Verification only: this package never signs and never handles secret keys, so the side-channel
properties of the backend are not relevant here (every input to ``verify`` is public).

Backends
--------
``dilithium-py`` (default, always installed)
    Pure-Python ML-DSA by Giacomo Pope (MIT). Installs anywhere with no compiler; tested by its author
    against the NIST FIPS 204 known-answer tests. Its README states it is not constant-time and not
    meant for production *signing* -- neither concern applies to public-key verification.
``pqcrypto`` (optional, ``pip install fractalai-pqc-verify[fast]``)
    CPython bindings to the PQClean C reference implementation (Apache-2.0); much faster than pure Python.

Neither is a FIPS 140-3 / CMVP validated module. Select with ``FRACTALAI_PQC_BACKEND`` =
``auto`` (default: pqcrypto if importable, else dilithium-py) | ``dilithium-py`` | ``pqcrypto``.
"""
from __future__ import annotations

import os
from typing import Callable

__all__ = ["PUBLIC_KEY_BYTES", "SIGNATURE_BYTES", "verify", "backend_name", "available_backends"]

PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309


def _dilithium_py() -> Callable[[bytes, bytes, bytes], bool]:
    from dilithium_py.ml_dsa import ML_DSA_65

    def _verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        return ML_DSA_65.verify(pk, msg, sig) is True

    return _verify


def _pqcrypto() -> Callable[[bytes, bytes, bytes], bool]:
    from pqcrypto.sign import ml_dsa_65

    def _verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            r = ml_dsa_65.verify(pk, msg, sig)  # returns None/True on success, raises on failure
        except Exception:
            return False
        return r is None or r is True

    return _verify


_LOADERS = {"dilithium-py": _dilithium_py, "pqcrypto": _pqcrypto}


def available_backends() -> list[str]:
    out = []
    for name, loader in _LOADERS.items():
        try:
            loader()
            out.append(name)
        except ImportError:
            pass
    return out


def _select(name: str | None) -> tuple[str, Callable[[bytes, bytes, bytes], bool]]:
    name = (name or os.environ.get("FRACTALAI_PQC_BACKEND") or "auto").strip().lower()
    if name == "auto":
        for candidate in ("pqcrypto", "dilithium-py"):
            try:
                return candidate, _LOADERS[candidate]()
            except ImportError:
                continue
        raise ImportError("no ML-DSA-65 backend installed (pip install dilithium-py)")
    if name not in _LOADERS:
        raise ValueError(f"unknown ML-DSA backend {name!r}; choose one of {sorted(_LOADERS)} or 'auto'")
    return name, _LOADERS[name]()


_cache: dict[str, tuple[str, Callable[[bytes, bytes, bytes], bool]]] = {}


def _get(name: str | None):
    key = name or os.environ.get("FRACTALAI_PQC_BACKEND") or "auto"
    if key not in _cache:
        _cache[key] = _select(name)
    return _cache[key]


def backend_name(backend: str | None = None) -> str:
    return _get(backend)[0]


def verify(public_key: bytes, message: bytes, signature: bytes, *, backend: str | None = None) -> bool:
    """FIPS 204 ML-DSA-65 ``Verify(pk, M, sigma)`` with an empty context string. Never raises:
    malformed inputs (wrong sizes, invalid hint encoding, ...) return ``False``."""
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    _, fn = _get(backend)
    try:
        return fn(bytes(public_key), bytes(message), bytes(signature)) is True
    except Exception:
        return False
