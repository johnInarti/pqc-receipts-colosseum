"""Regression tests for the 2026-10-06 adversarial review (findings F1-F11). Offline."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import textwrap

import pytest

from fractalai_pqc_verify import load_key_directory, verify_receipt
from fractalai_pqc_verify.directory import KeyDirectory, verify_directory
from fractalai_pqc_verify.profiles import strict_b64, strict_b64url, verify_profile
from fractalai_pqc_verify.conformance import load_vectors

from conftest import FIXTURES

VEC = {v["profile"]: v for _, v in load_vectors()}


@pytest.fixture
def active(directory_json):
    return [k["public_key_b64"] for k in directory_json["keys"] if k["status"] == "active"]


def test_genuine_receipt_still_valid(midas_receipt, active, backend):
    r = verify_receipt(midas_receipt, active)
    assert r.valid, r.reason
    assert r.checks["snapshot_matches_signed_hash"] is True


def test_f1_profile_field_cannot_reroute_a_tampered_served_receipt(midas_receipt, active):
    r = copy.deepcopy(midas_receipt)
    r["facts"]["health_factor"] = 0.42
    r["canonical"] = r["canonical"].replace("health_factor=1.000872452215302", "health_factor=0.42")
    r.update({"profile": "x402-served", "domain": "FRACTALAI-x402-served-v1", "route_id": "midas-alert",
              "digest": r["receipt_id"], "signed_message": r["served_message"]})
    res = verify_receipt(r, active)
    assert not res.valid and "ambiguous" in res.reason


def test_f1b_expected_profile_and_explicit_route_are_enforced():
    v = VEC["x402-served"]
    trusted = [v["trusted_public_key"]]
    assert verify_receipt(v["valid"], trusted).valid  # generic use unchanged
    assert not verify_receipt(v["valid"], trusted, expected_profile="served").valid
    assert not verify_receipt(v["valid"], trusted, expected_route="midas-alert").valid
    assert verify_receipt(v["valid"], trusted, expected_route=v["valid"]["route_id"]).valid


def test_served_path_refuses_reserved_acp_route(midas_receipt, active):
    r = copy.deepcopy(midas_receipt)
    r["served_message"] = r["served_message"].replace("midas-alert", "x402-attest-decision")
    assert not verify_receipt(r, active, expected_route=None).checks["domain_string_matches"]


@pytest.mark.parametrize("mutate", [
    lambda r: r["snapshot"]["row"].__setitem__("debt_usd", 1),
    lambda r: r["facts"].__setitem__("recommended_action", "liquidate-now"),
    lambda r: r.__setitem__("emitted_at", "0"),
    lambda r: r.__setitem__("snapshot", [[[[]]]]),
])
def test_f2_unsigned_snapshot_extra_facts_and_emitted_at_are_rejected(midas_receipt, active, mutate):
    r = copy.deepcopy(midas_receipt)
    mutate(r)
    res = verify_receipt(r, active)
    assert not res.valid and not res.signature_valid, res.reason


@pytest.mark.parametrize("bad", ["QUJD\n", "QUJD\n\n", " QUJD"])
def test_f3_strict_base64_rejects_trailing_newline(bad):
    with pytest.raises(ValueError):
        strict_b64(bad)
    with pytest.raises(ValueError):
        strict_b64url(bad)


def test_f3_jws_signature_with_trailing_newline_is_rejected():
    v = copy.deepcopy(VEC["jose-ml-dsa-65"]["valid"])
    v["jws"] += "\n"
    assert not verify_profile("jose-ml-dsa-65", v, [VEC["jose-ml-dsa-65"]["trusted_public_key"]]).valid


def test_f4_nan_infinity_tokens_are_not_json(midas_receipt, active):
    for tok in ("NaN", "Infinity", "-Infinity"):
        text = json.dumps(midas_receipt)[:-1] + f', "x": {tok}}}'
        assert not verify_receipt(text, active).valid


def test_f7_deep_nesting_is_a_rejection_not_a_crash(midas_receipt, active):
    r = copy.deepcopy(midas_receipt)
    deep = 0
    for _ in range(5000):
        deep = [deep]
    r["facts"]["chain_id"] = deep
    assert not verify_receipt(r, active).valid
    assert not verify_receipt('{"canonical":' + "[" * 100000 + "]" * 100000 + "}", active).valid


def test_f8_cli_ignores_unsigned_emitted_at_by_default(midas_receipt):
    from fractalai_pqc_verify import cli
    forged = dict(midas_receipt, emitted_at="0")
    assert cli._emitted_at(forged) is None  # current time, not attacker-chosen
    args = cli.build_parser().parse_args(["receipt", "x.json", "--include-retiring", "--trust-receipt-time"])
    assert cli._emitted_at(forged, args) == 1790473960  # the SIGNED value from `canonical`


def test_f8b_unparsable_not_after_is_not_trusted(directory_json):
    d = load_key_directory(directory_json, governance_key=directory_json["directory_public_key"])
    keys = [dict(k) for k in d.keys]
    for k in keys:
        if k["status"] == "retiring":
            k["not_after"] = "soon"
            rk = k["public_key_b64"]
    fake = KeyDirectory(raw={**d.raw, "keys": keys}, source="t", trust_basis="t", verification=d.verification)
    assert rk not in fake.trusted_keys(include_retiring=True, now=0)
    keys[0]["not_after"] = "1798246800"
    assert rk in fake.trusted_keys(include_retiring=True, now=0)


def test_f9_noop_backend_shadow_is_refused(tmp_path, midas_receipt):
    pkg = tmp_path / "pqcrypto" / "sign"
    pkg.mkdir(parents=True)
    (tmp_path / "pqcrypto" / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "ml_dsa_65.py").write_text("def verify(pk, m, s):\n    return None\n")
    code = textwrap.dedent(f"""
        import sys, json; sys.path.insert(0, {str(tmp_path)!r})
        from fractalai_pqc_verify import verify_receipt, mldsa
        r = json.load(open({str(FIXTURES / 'midas-alert-fe62b072.json')!r}))
        r['signature'] = 'AAAA' + r['signature'][4:]
        print(mldsa.backend_name(), verify_receipt(r, [r['public_key']]).valid)
    """)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert out.stdout.split() == ["dilithium-py", "False"], out.stdout + out.stderr


def test_f9b_bad_backend_env_is_a_rejection_not_a_crash(midas_receipt, monkeypatch):
    from fractalai_pqc_verify import mldsa
    monkeypatch.setenv("FRACTALAI_PQC_BACKEND", "no-such-backend")
    mldsa._cache.clear()
    res = verify_receipt(midas_receipt, [midas_receipt["public_key"]])
    assert not res.valid and "backend_error" in res.checks


def test_f10_directory_is_frozen_after_verification(directory_json):
    raw = copy.deepcopy(directory_json)
    d = load_key_directory(raw, governance_key=raw["directory_public_key"])
    raw["keys"].append({"public_key_b64": "ATTACKER", "status": "active"})
    assert "ATTACKER" not in d.trusted_keys()


@pytest.mark.parametrize("keys", [None, "", 0, False, {}])
def test_f11_directory_keys_must_be_a_list(directory_json, keys):
    d = dict(directory_json, keys=keys)
    assert verify_directory(d, governance_key=directory_json["directory_public_key"]).reason == "directory keys is not a list"


def test_f6_fetch_refuses_https_to_http_redirect():
    from fractalai_pqc_verify._safe import _HttpsOnlyRedirect
    import urllib.error
    import urllib.request
    req = urllib.request.Request("https://example.invalid/keys")
    with pytest.raises(urllib.error.URLError):
        _HttpsOnlyRedirect().redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/latest")
