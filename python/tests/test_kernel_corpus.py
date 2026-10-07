"""Trust Kernel v2 (Python port) against the shared adversarial corpus — must be 100 %."""
from __future__ import annotations

from pathlib import Path

import pytest

from fractalai_pqc_verify.kernel import SELF_TEST, verify
from fractalai_pqc_verify.kernel.corpus import run

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "corpus"
KDIR = Path(__file__).resolve().parents[1] / "src" / "fractalai_pqc_verify" / "kernel"


def test_self_test_passes():
    assert SELF_TEST["ok"] and SELF_TEST["mldsa_kat"] and SELF_TEST["strict_json_parser"]


@pytest.mark.skipif(not CORPUS.exists(), reason="corpus/ not present (installed package)")
def test_corpus_100_percent():
    passed, fails, total = run(CORPUS)
    assert not fails, fails[:3]
    assert passed == total > 100


@pytest.mark.skipif(not (REPO / "kernel" / "trust-roots.json").exists(), reason="JS kernel not present")
@pytest.mark.parametrize("name", ["trust-roots.json", "checkpoint-directory.json"])
def test_baked_roots_identical_to_js_kernel(name):
    assert (KDIR / name).read_bytes() == (REPO / "kernel" / name).read_bytes()


def test_never_raises_on_hostile_input():
    for x in [None, 42, "", "[]", '{"canonical":{}}', b"\xff\xfe", "[" * 100000]:
        v = verify(x, kinds=["midas-alert", "x402-seal"], directory="{}")
        assert v["valid"] is False and v["reasons"]
