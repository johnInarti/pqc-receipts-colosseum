"""Same-origin relocation of the FRACTALAI-key-directory-v1 chain (mirror of kernel/test/locate.test.mjs)."""
import json
from pathlib import Path

import pytest

from fractalai_pqc_verify import directory as d

LEGACY = json.loads((Path(__file__).resolve().parents[2] / "kernel" / "checkpoint-directory.json").read_text())
SPEC = {"spec": "x402-receipt-key-directory/1", "issuer": "https://fractalai.net.co", "epoch": 1}
OLD = "https://fractalai.net.co/.well-known/x402-receipt-keys"
NEW = "https://fractalai.net.co/.well-known/fractalai-key-directory"


def fake(monkeypatch, routes):
    seen = []

    def get(url, **_kw):
        seen.append(url)
        if url not in routes:
            raise OSError("HTTP 404")
        return routes[url], url

    monkeypatch.setattr(d, "https_get_json", get)
    monkeypatch.setattr(d, "_check", lambda raw, final_url, **_kw: (raw, final_url))
    return seen


def test_legacy_at_old_path(monkeypatch):
    seen = fake(monkeypatch, {OLD: LEGACY})
    assert d.fetch_key_directory(OLD) == (LEGACY, OLD) and seen == [OLD]


def test_relocates_when_old_path_serves_spec_format(monkeypatch):
    fake(monkeypatch, {OLD: SPEC, NEW: LEGACY})
    assert d.fetch_key_directory(OLD) == (LEGACY, NEW)


def test_relocates_on_404(monkeypatch):
    fake(monkeypatch, {NEW: LEGACY})
    assert d.fetch_key_directory(OLD)[1] == NEW


def test_spec_format_never_accepted(monkeypatch):
    fake(monkeypatch, {OLD: SPEC, NEW: SPEC})
    with pytest.raises(d.KeyDirectoryError):
        d.fetch_key_directory(OLD)


def test_forged_pointer_ignored(monkeypatch):
    seen = fake(monkeypatch, {OLD: {**SPEC, "legacy": "https://evil.example/x"}, NEW: LEGACY})
    assert d.fetch_key_directory(OLD)[1] == NEW and all(u.startswith("https://fractalai.net.co/") for u in seen)


def test_no_loop_on_legacy_path(monkeypatch):
    seen = fake(monkeypatch, {NEW: SPEC})
    with pytest.raises(d.KeyDirectoryError):
        d.fetch_key_directory(NEW)
    assert seen == [NEW]
