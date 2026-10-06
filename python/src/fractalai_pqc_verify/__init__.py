"""Offline verifier for FractalAI post-quantum (ML-DSA-65, FIPS 204) signed receipts.

    >>> from fractalai_pqc_verify import fetch_key_directory, verify_receipt
    >>> directory = fetch_key_directory()            # verified: signature, root, kid binding
    >>> result = verify_receipt(receipt, directory)  # trusted set = keys with status "active"
    >>> result.valid, result.reason

Fail-closed: ``valid`` is True only if the ML-DSA-65 signature verifies AND the signing key is in your
trusted set. Verification is fully offline once you hold the receipt and the trusted keys.
"""
from .conformance import run_conformance
from .directory import (
    DEFAULT_DIRECTORY_URL,
    KeyDirectory,
    KeyDirectoryError,
    fetch_key_directory,
    load_key_directory,
    verify_directory,
)
from .jcs import canonicalize
from .mldsa import backend_name
from .profiles import PROFILES, VerificationResult, verify_profile
from .receipt import fetch_midas_receipt, verify_receipt

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_DIRECTORY_URL",
    "PROFILES",
    "KeyDirectory",
    "KeyDirectoryError",
    "VerificationResult",
    "__version__",
    "backend_name",
    "canonicalize",
    "fetch_key_directory",
    "fetch_midas_receipt",
    "load_key_directory",
    "run_conformance",
    "verify_directory",
    "verify_profile",
    "verify_receipt",
]
