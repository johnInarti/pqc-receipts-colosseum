"""The real public MIDAS alert receipt fe62b072... verified fully offline from saved fixtures."""
import copy
import json

import pytest

from fractalai_pqc_verify import KeyDirectoryError, load_key_directory, verify_directory, verify_receipt
from fractalai_pqc_verify.directory import directory_root

ACTIVE_KID = "86c139c960bb274c"


def _trusted(directory_json):
    return [k["public_key_b64"] for k in directory_json["keys"] if k["status"] == "active"]


def test_genuine_receipt_with_active_key_is_valid(midas_receipt, directory_json, backend):
    r = verify_receipt(midas_receipt, _trusted(directory_json))
    assert r.valid, r.reason
    assert r.checks["receipt_id_is_sha256_of_canonical"]
    assert r.checks["domain_string_matches"]
    assert r.checks["ml_dsa65_signature_valid"]
    assert r.checks["facts_match_canonical"]
    assert r.checks["signed_facts"]["risk_tier"] == "critical"


def test_accepts_json_text_and_key_directory_object(midas_receipt, directory_json):
    d = load_key_directory(directory_json)
    assert verify_receipt(json.dumps(midas_receipt), d).valid


def test_no_trust_anchor_is_rejected(midas_receipt):
    r = verify_receipt(midas_receipt, None)
    assert r.valid is False and r.signature_valid is True and "UNVERIFIED" in r.reason


def test_retiring_or_reserved_key_is_not_trusted_by_default(midas_receipt, directory_json):
    others = [k["public_key_b64"] for k in directory_json["keys"] if k["status"] != "active"]
    r = verify_receipt(midas_receipt, others)
    assert r.valid is False and r.signature_valid is True and r.key_trusted is False


@pytest.mark.parametrize(
    "field,mutate",
    [
        ("canonical", lambda s: s.replace("risk_tier=critical", "risk_tier=low")),
        ("served_message", lambda s: s.replace("midas-alert", "x402-attest-decision")),
        ("receipt_id", lambda s: "0" + s[1:]),
        ("signature", lambda s: ("A" if s[0] != "A" else "B") + s[1:]),
    ],
)
def test_tampered_receipt_is_rejected(midas_receipt, directory_json, field, mutate, backend):
    t = copy.deepcopy(midas_receipt)
    t[field] = mutate(t[field])
    r = verify_receipt(t, _trusted(directory_json))
    assert r.valid is False and r.signature_valid is False, r.reason


def test_unsigned_facts_contradicting_signed_text_are_rejected(midas_receipt, directory_json):
    t = copy.deepcopy(midas_receipt)
    t["facts"]["health_factor"] = 2.5  # looks healthy, but the signed canonical says 1.00087
    r = verify_receipt(t, _trusted(directory_json))
    assert r.valid is False and "health_factor" in r.reason


def test_wrong_expected_route_is_rejected(midas_receipt, directory_json):
    assert verify_receipt(midas_receipt, _trusted(directory_json), expected_route="x402-witness").valid is False
    assert verify_receipt(midas_receipt, _trusted(directory_json), expected_route=None).valid is True


def test_different_key_forgery_is_rejected(midas_receipt, directory_json, backend):
    import base64

    from dilithium_py.ml_dsa import ML_DSA_65

    pk, sk = ML_DSA_65.keygen()
    forged = copy.deepcopy(midas_receipt)
    forged["public_key"] = base64.b64encode(pk).decode()
    forged["signature"] = base64.b64encode(ML_DSA_65.sign(sk, forged["served_message"].encode())).decode()
    r = verify_receipt(forged, _trusted(directory_json))
    assert r.signature_valid is True, "attacker signature verifies over its own bytes"
    assert r.valid is False and r.key_trusted is False


# --- key directory (offline) ---------------------------------------------------------------------

def test_directory_integrity_and_pinning(directory_json, backend):
    v = verify_directory(directory_json)
    assert v.signature_valid and not v.valid  # self-signed only: integrity yes, authorship unverified
    pinned = verify_directory(directory_json, governance_key=directory_json["directory_public_key"])
    assert pinned.valid, pinned.reason
    anchored = verify_directory(directory_json, anchored_root=directory_json["root"], expected_prev_root=directory_json["prev_root"])
    assert anchored.valid, anchored.reason
    assert directory_root(directory_json["keys"], directory_json["prev_root"], directory_json["epoch"], directory_json["directory_public_key"]) == directory_json["root"]


def test_directory_tampering_is_rejected(directory_json):
    t = copy.deepcopy(directory_json)
    for k in t["keys"]:
        if k["status"] == "reserved":
            k["status"] = "active"  # promote a reserved key without the governance key
            break
    assert verify_directory(t).signature_valid is False
    with pytest.raises(KeyDirectoryError):
        load_key_directory(t)


def test_directory_wrong_pin_is_rejected(directory_json):
    other = directory_json["keys"][0]["public_key_b64"]
    with pytest.raises(KeyDirectoryError):
        load_key_directory(directory_json, governance_key=other)
    with pytest.raises(KeyDirectoryError):
        load_key_directory(directory_json, anchored_root="00" * 32)


def test_directory_trusted_key_policy(directory_json):
    d = load_key_directory(directory_json)
    assert d.trust_basis == "local-file"
    active = d.trusted_keys()
    assert len(active) == 1 and d.status_of(active[0]) == "active"
    retiring = [k for k in d.keys if k["status"] == "retiring"][0]
    na = int(retiring["not_after"])
    assert retiring["public_key_b64"] in d.trusted_keys(include_retiring=True, now=na)
    assert retiring["public_key_b64"] not in d.trusted_keys(include_retiring=True, now=na + 1)
