"""The 7 golden vectors from conformance/vectors: genuine accepts, no-trust rejects, tampered rejects,
different-key forgery rejects (with its own signature verifying)."""
import copy

import pytest

from fractalai_pqc_verify import PROFILES, run_conformance, verify_profile, verify_receipt
from fractalai_pqc_verify.conformance import bundled_vectors

VECTORS = list(bundled_vectors())


def test_all_seven_profiles_have_a_vector():
    assert len(VECTORS) == 7
    assert sorted(v["profile"] for _, v in VECTORS) == sorted(PROFILES)


@pytest.mark.parametrize("name,vec", VECTORS, ids=[n for n, _ in VECTORS])
def test_genuine_with_trusted_key_is_valid(name, vec, backend):
    r = verify_profile(vec["profile"], vec["valid"], [vec["trusted_public_key"]], backend=backend)
    assert r.valid and r.signature_valid and r.key_trusted, r.reason


@pytest.mark.parametrize("name,vec", VECTORS, ids=[n for n, _ in VECTORS])
def test_genuine_without_trust_is_rejected(name, vec, backend):
    r = verify_profile(vec["profile"], vec["valid"], None, backend=backend)
    assert r.valid is False and r.signature_valid is True and r.key_trusted is False
    assert "UNVERIFIED" in r.reason
    # an empty trusted set is also a rejection
    assert verify_profile(vec["profile"], vec["valid"], [], backend=backend).valid is False


@pytest.mark.parametrize("name,vec", VECTORS, ids=[n for n, _ in VECTORS])
def test_tampered_is_rejected(name, vec, backend):
    r = verify_profile(vec["profile"], vec["tampered"], [vec["trusted_public_key"]], backend=backend)
    assert r.valid is False and r.signature_valid is False, r.reason


@pytest.mark.parametrize("name,vec", VECTORS, ids=[n for n, _ in VECTORS])
def test_different_key_forgery_is_rejected(name, vec, backend):
    r = verify_profile(vec["profile"], vec["forged"], [vec["trusted_public_key"]], backend=backend)
    assert r.valid is False
    assert r.signature_valid is True, "forgery must carry a VALID signature by the attacker key"
    assert r.key_trusted is False


@pytest.mark.parametrize("name,vec", VECTORS, ids=[n for n, _ in VECTORS])
def test_verify_receipt_dispatches_profiles(name, vec, backend):
    assert verify_receipt(vec["valid"], vec["trusted_public_key"]).valid is True
    assert verify_receipt(vec["forged"], [vec["trusted_public_key"]]).valid is False


@pytest.mark.parametrize("name,vec", VECTORS, ids=[n for n, _ in VECTORS])
def test_malformed_input_never_raises(name, vec):
    broken = copy.deepcopy(vec["valid"])
    for k in list(broken):
        if k != "profile":
            broken[k] = None
    r = verify_profile(vec["profile"], broken, [vec["trusted_public_key"]])
    assert r.valid is False


def test_run_conformance_7_of_7(backend):
    rows = run_conformance(backend=backend)
    assert len(rows) == 7 and all(r.ok for r in rows)


def test_unknown_profile():
    assert verify_profile("nope", {}, ["x"]).valid is False


def test_reserved_route_refused_by_generic_profile():
    vec = dict(VECTORS)["x402-served.json"]
    e = dict(vec["valid"], route_id="x402-attest-decision")
    r = verify_profile("x402-served", e, [vec["trusted_public_key"]])
    assert r.valid is False and "reserved" in r.reason
