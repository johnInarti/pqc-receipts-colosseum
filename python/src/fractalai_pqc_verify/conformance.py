"""Python port of ``conformance/src/check.mjs``: for every golden vector prove the verifier is fail-closed.

* genuine  (issuer key pinned as trusted) -> valid
* no trust (same genuine receipt, ``trusted_keys=None``) -> NOT valid
* tampered (issuer key, edited bytes) -> NOT valid
* forged   (attacker key + own content; its signature verifies) -> NOT valid, ``signature_valid`` True
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

from .profiles import PROFILES, verify_profile

__all__ = ["ConformanceRow", "bundled_vectors", "load_vectors", "run_conformance"]


@dataclass(frozen=True)
class ConformanceRow:
    profile: str
    genuine: bool
    fail_closed: bool
    tamper_rejected: bool
    forge_rejected: bool

    @property
    def ok(self) -> bool:
        return self.genuine and self.fail_closed and self.tamper_rejected and self.forge_rejected


def bundled_vectors() -> Iterator[tuple[str, dict[str, Any]]]:
    """The 7 golden vectors shipped inside the wheel (identical copies of ``conformance/vectors``)."""
    root = resources.files("fractalai_pqc_verify") / "vectors"
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".json"):
            yield entry.name, json.loads(entry.read_text("utf-8"))


def load_vectors(directory: str | Path | None = None) -> list[tuple[str, dict[str, Any]]]:
    if directory is None:
        return list(bundled_vectors())
    d = Path(directory)
    return [(p.name, json.loads(p.read_text("utf-8"))) for p in sorted(d.glob("*.json"))]


def check_vector(v: dict[str, Any], *, backend: str | None = None) -> ConformanceRow:
    profile = v["profile"]
    trusted = [v["trusted_public_key"]]
    genuine = verify_profile(profile, v["valid"], trusted, backend=backend).valid is True
    fail_closed = verify_profile(profile, v["valid"], None, backend=backend).valid is False
    tamper_rejected = verify_profile(profile, v["tampered"], trusted, backend=backend).valid is False
    fr = verify_profile(profile, v["forged"], trusted, backend=backend)
    forge_rejected = fr.valid is False and fr.signature_valid is True  # signature ok, key untrusted
    return ConformanceRow(profile, genuine, fail_closed, tamper_rejected, forge_rejected)


def run_conformance(directory: str | Path | None = None, *, backend: str | None = None) -> list[ConformanceRow]:
    return [check_vector(v, backend=backend) for _, v in load_vectors(directory)]


def missing_profiles(rows: list[ConformanceRow]) -> list[str]:
    return [p for p in PROFILES if not any(r.profile == p for r in rows)]
