"""Spec 2.1 §12 (latam-stablecoin-receipt) — Python port: helpers + offline behaviour, mirroring kernel/test/stablecoin.test.mjs."""
import copy
import json
from pathlib import Path

import pytest

from fractalai_pqc_verify.kernel import C, verify
from fractalai_pqc_verify.kernel._stablecoin import BAKED_STABLECOIN_REGISTRY, abi_decode_string, abi_decode_uint8, check_registry, format_units

VEC = Path(__file__).resolve().parents[2] / "corpus" / "vectors" / "P30-stablecoin-copm-polygon-two-rpcs.json"


def _p30():
    if not VEC.exists():
        pytest.skip("corpus not available next to the installed package")
    return json.loads(VEC.read_text("utf-8"))


def test_format_units():
    assert format_units("667703000000000000000000", 18) == "667703"
    assert format_units("18139674", 6) == "18.139674"
    assert format_units("1", 18) == "0.000000000000000001"
    assert format_units("627114637588570086999", 18) == "627.114637588570086999"


def test_abi_decoding_is_strict():
    def s(t, extra=""):
        return "0x" + "20".rjust(64, "0") + format(len(t), "x").rjust(64, "0") + t.encode().hex().ljust(64, "0") + extra
    assert abi_decode_string(s("COPM")) == "COPM"
    for bad in (s("COPM", "00" * 32), s("COPM")[:-2] + "01", "0x434f504d", "0x" + "20".rjust(64, "0") + "2".rjust(64, "0") + "c328".ljust(64, "0")):
        with pytest.raises(Exception) as e:
            abi_decode_string(bad)
        assert e.value.code == C.PAYMENT_TOKEN_METADATA
    assert abi_decode_uint8("0x" + "12".rjust(64, "0")) == 18


def test_registry_and_overrides():
    assert check_registry(BAKED_STABLECOIN_REGISTRY).id == "fractalai.latam-stablecoins/1"
    p = _p30()
    rec, keys, now = json.dumps(p["input"]["receipt"]), json.dumps([p["input"]["receipt"]["public_key"]]), p["context"]["now"]
    dup = copy.deepcopy(BAKED_STABLECOIN_REGISTRY)
    dup["tokens"].append(dup["tokens"][0])
    v = verify(rec, kind="latam-stablecoin-receipt", trusted_keys=keys, token_registry=json.dumps(dup), now=now)
    assert v["reasons"][0]["code"] == C.REGISTRY_INVALID
    ok = verify(rec, kind="latam-stablecoin-receipt", trusted_keys=keys, now=now)
    assert ok["valid"] is True and ok["levels"]["onchain"] is None


def test_kernel_registry_identical_to_js():
    js = Path(__file__).resolve().parents[2] / "kernel" / "latam-stablecoins.json"
    if not js.exists():
        pytest.skip("JS kernel not available")
    assert json.loads(js.read_text("utf-8")) == BAKED_STABLECOIN_REGISTRY
