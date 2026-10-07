"""The decision algorithm — Python mirror of kernel/src/verify.mjs (spec/TRUST-KERNEL.md §9).
Never raises on hostile input: every failure becomes a coded reason in a leveled verdict."""
from __future__ import annotations

import base64
import copy
import json
import time
from importlib import resources

from ._anchors import default_transport, verify_evm_anchor, verify_solana_anchor
from ._codes import DEFAULT_REQUIRE, EXIT, KERNEL_ID, LEVELS, SPEC_VERSION, C, KernelError
from ._crypto import kid_for_key, mldsa_verify
from ._hygiene import assert_json_value, is_safe_int, parse_json_strict
from ._model import KINDS, anchor_ids, infer_kind, key_authorizes, parse_receipt, verify_directory_chain


def _load(name):
    return json.loads((resources.files(__package__) / name).read_text("utf-8"))


BAKED_ROOTS = _load("trust-roots.json")
_cp = _load("checkpoint-directory.json")
BAKED_CHECKPOINT_DIRECTORY = _cp if _cp.get("root") == BAKED_ROOTS["directory_checkpoint"]["root"] else None


def _self_test() -> dict:
    kat = _load("kat.json")
    try:
        pk = base64.b64decode(kat["public_key"], validate=True)
        sig = base64.b64decode(kat["signature"], validate=True)
        msg = kat["message"].encode("utf-8")
        flipped = bytearray(sig); flipped[17] ^= 1
        kat_ok = mldsa_verify(sig, msg, pk) is True and mldsa_verify(bytes(flipped), msg, pk) is False and mldsa_verify(sig, msg + b"x", pk) is False
    except Exception:  # noqa: BLE001
        kat_ok = False
    probes = [('{" ":0,"\\ud800\\udc00":1}', [[0x20], [0x10000]]), ('{"amount":"100","\\u0041":"x"}', [[0x61, 0x6D, 0x6F, 0x75, 0x6E, 0x74], [0x41]])]
    parser_ok = True
    for text, want in probes:
        try:
            got = [[ord(c) for c in k] for k in parse_json_strict(text)]
            parser_ok = parser_ok and got == want
        except KernelError:
            parser_ok = False
    return {"ok": kat_ok and parser_ok, "mldsa_kat": kat_ok, "strict_json_parser": parser_ok, "native_json_key_cache_ok": True}


SELF_TEST = _self_test()


def _value(x):
    if isinstance(x, (str, bytes, bytearray)):
        return parse_json_strict(x)
    return copy.deepcopy(assert_json_value(x))


def _policy(p):
    p = p or {}
    req = list(p.get("require") or DEFAULT_REQUIRE)
    for lv in req:
        if lv not in LEVELS:
            raise KernelError(C.INPUT_SHAPE, f"unknown level {lv} in policy.require")
    if "integrity" not in req:
        req.insert(0, "integrity")
    num = lambda k, d, lo: p[k] if is_safe_int(p.get(k)) and p[k] >= lo else d  # noqa: E731
    return {"require": req, "allow_testnet_anchors": p.get("allow_testnet_anchors") is True, "require_known_anchorer": p.get("require_known_anchorer") is True,
            "min_confirmations": num("min_confirmations", 1, 0), "rpc_quorum": num("rpc_quorum", 1, 1), "skew": num("max_clock_skew_sec", 900, 0)}


def verify(receipt, *, kind=None, kinds=None, expected_id=None, directory=None, directory_history=None, trusted_keys=None,
           governance_key=None, roots=None, checkpoint=None, allow_tls_directory=False, check_anchors=False, anchors=None, rpc=None,
           solana_signers=None, policy=None, now=None, transport=None) -> dict:
    v = {"kernel": KERNEL_ID, "spec_version": SPEC_VERSION, "kind": None, "valid": False,
         "levels": {"integrity": False, "authentic": False, "trusted": False, "time_anchored": None, "finalized": None},
         "trust_basis": "none", "policy": None, "key": None, "directory": None, "signed": None, "signed_time": None,
         "anchors": [], "overrides": [], "ignored_unsigned_fields": [], "reasons": [], "exit_code": EXIT["integrity"],
         "engine": {"self_test_ok": SELF_TEST["ok"], "native_json_key_cache_ok": True}}

    def reason(level, e):
        v["reasons"].append({"level": level, "code": e.code if isinstance(e, KernelError) else C.INTERNAL,
                             "detail": e.detail if isinstance(e, KernelError) else f"{type(e).__name__}: {e}"})

    def finish():
        req = v["policy"]["require"] if v["policy"] else list(DEFAULT_REQUIRE)
        v["valid"] = bool(v["policy"]) and all(v["levels"][lv] is True for lv in req)
        first = next((lv for lv in req if v["levels"][lv] is not True), "integrity")
        v["exit_code"] = EXIT["VALID"] if v["valid"] else EXIT[first]
        return v

    try:
        if not SELF_TEST["ok"]:
            reason("integrity", KernelError(C.ENGINE_SELFTEST_FAILED, f"kernel self-test failed: {SELF_TEST}"))
            return finish()
        pol = _policy(policy)
        v["policy"] = pol
        now = now if is_safe_int(now) else int(time.time())
        transport = transport or default_transport
        # 1. integrity
        try:
            r = _value(receipt)
            if not isinstance(r, dict):
                raise KernelError(C.INPUT_SHAPE, "receipt is not a JSON object")
            allowed = [kind] if kind is not None else list(kinds) if isinstance(kinds, (list, tuple)) else None
            if not allowed:
                raise KernelError(C.KIND_UNKNOWN, "policy must name the expected kind(s) — the document never chooses")
            for k in allowed:
                if k not in KINDS:
                    raise KernelError(C.KIND_UNKNOWN, f"unknown kind {k!r}")
            k = allowed[0] if len(allowed) == 1 else infer_kind(r)
            if k not in allowed:
                raise KernelError(C.KIND_NOT_ALLOWED, f"receipt looks like {k}, policy allows {', '.join(allowed)}")
            v["kind"] = k
            p = parse_receipt(r, k)
            if expected_id is not None and expected_id != p["content_id"]:
                raise KernelError(C.EXPECTED_ID_MISMATCH, "the receipt is not the one that was requested (content id differs)")
            v["levels"]["integrity"] = True
            v["ignored_unsigned_fields"] = p["ignored"]
            v["signed_time"] = p["signed_time"]
        except Exception as e:  # noqa: BLE001
            reason("integrity", e)
            return finish()
        # 2. authentic
        if not mldsa_verify(p["sig"], p["message"].encode("utf-8"), p["pk"]):
            reason("authentic", KernelError(C.SIGNATURE_INVALID, f"ML-DSA-65 signature does not verify over the reconstructed {p['kind']} message"))
            return finish()
        v["levels"]["authentic"] = True
        v["signed"] = p["signed"]
        v["key"] = {"kid": kid_for_key(p["public_key_b64"])}
        # 3. anchors
        want = check_anchors is True or "time_anchored" in pol["require"] or "finalized" in pol["require"]
        anchor_time = None
        if want:
            v["levels"]["time_anchored"] = False
            v["levels"]["finalized"] = False
            refs = []
            try:
                raw = _value(anchors) if anchors is not None else r.get("anchors") if "anchors" in r else [r["anchor"]] if "anchor" in r else []
                refs = raw if isinstance(raw, list) else [raw]
                if not refs:
                    raise KernelError(C.NO_ANCHOR, "no anchor reference supplied")
                if len(refs) > 8:
                    raise KernelError(C.ANCHOR_REF_MALFORMED, "more than 8 anchor references")
            except KernelError as e:
                reason("time_anchored", e)
                refs = []
            if solana_signers is not None:
                v["overrides"].append("solanaSigners")
            rts = roots if roots is not None else BAKED_ROOTS
            ids = anchor_ids(p)
            for ref in refs:
                rec = {"ref": None, "ok": False, "counts": False, "facts": None, "reason": None}
                try:
                    if not isinstance(ref, dict):
                        raise KernelError(C.ANCHOR_REF_MALFORMED, "anchor reference is not an object")
                    is_sol = ref.get("chain") == "solana"
                    rec["ref"] = f"solana:{ref.get('cluster')}" if is_sol else f"eip155:{ref.get('chain_id')}"
                    ctx = {"roots": rts, "ids": ids, "signed_time": p["signed_time"], "policy": pol, "transport": transport,
                           "rpc_urls": (rpc or {}).get(rec["ref"]), "solana_signers": solana_signers}
                    f = verify_solana_anchor(ref, ctx) if is_sol else verify_evm_anchor(ref, ctx)
                    rec["ok"], rec["facts"] = True, f
                    if f["network_class"] != "production" and not pol["allow_testnet_anchors"]:
                        raise KernelError(C.ANCHOR_TESTNET_NOT_ALLOWED, f"{rec['ref']} is a test network; policy.allowTestnetAnchors is false")
                    if pol["require_known_anchorer"] and not f["anchorer_known"]:
                        raise KernelError(C.ANCHOR_ANCHORER_UNKNOWN, f"anchored by {f.get('anchored_by')}, not a known FractalAI anchorer")
                    rec["counts"] = True
                except Exception as e:  # noqa: BLE001
                    rec["reason"] = {"code": e.code if isinstance(e, KernelError) else C.INTERNAL, "detail": e.detail if isinstance(e, KernelError) else str(e)}
                    v["reasons"].append({"level": "time_anchored", "code": rec["reason"]["code"], "detail": f"{rec['ref'] or 'anchor'}: {rec['reason']['detail']}"})
                v["anchors"].append(rec)
            counted = [a for a in v["anchors"] if a["counts"]]
            if counted:
                v["levels"]["time_anchored"] = True
                anchor_time = min(a["facts"]["time"] for a in counted)
                v["levels"]["finalized"] = any(a["facts"]["finalized"] is True for a in counted)
                if not v["levels"]["finalized"]:
                    v["reasons"].append({"level": "finalized", "code": C.NOT_FINALIZED, "detail": "no counted anchor is in a finalized block yet"})
        # 4. trusted
        try:
            spec = KINDS[p["kind"]]
            if trusted_keys is not None:
                tk = _value(trusted_keys)
                if not isinstance(tk, list) or not tk or any(not isinstance(x, str) for x in tk):
                    raise KernelError(C.NO_TRUST_SOURCE, "trustedKeys must be a non-empty array of base64 keys")
                v["overrides"].append("trustedKeys")
                v["trust_basis"] = "override"
                if p["signed_time"] is not None and p["signed_time"] > now + pol["skew"]:
                    raise KernelError(C.SIGNED_TIME_IN_FUTURE, f"signed time {p['signed_time']} is in the future")
                if p["public_key_b64"] not in tk:
                    raise KernelError(C.KEY_NOT_IN_PINNED_SET, "signing key is not in the pinned trustedKeys set")
                v["key"]["time_basis"] = "verification-time" if p["signed_time"] is None else "signed"
                v["levels"]["trusted"] = True
            else:
                if spec["trust"] == "pinned-set-only":
                    raise KernelError(C.SELF_ATTEST_NOT_TRUSTED, "a self-attest seal is signed by the seller; only an explicit trustedKeys set can trust it")
                if directory is None:
                    raise KernelError(C.NO_TRUST_SOURCE, "no key directory supplied")
                rts = roots if roots is not None else BAKED_ROOTS
                if roots is not None:
                    v["overrides"].append("roots")
                gk = (rts.get("governance") or {}).get("public_key_b64")
                dc = rts.get("directory_checkpoint")
                cp = {"epoch": dc["epoch"], "root": dc["root"], "directory": BAKED_CHECKPOINT_DIRECTORY if rts is BAKED_ROOTS else None} if dc else None
                if governance_key is not None:
                    v["overrides"].append("governanceKey")
                    if governance_key != gk:
                        cp = checkpoint
                    gk = governance_key
                if allow_tls_directory:
                    v["overrides"].append("allowTlsDirectory")
                    cp = None
                d = _value(directory)
                hist = _value(directory_history) if directory_history is not None else []
                res = verify_directory_chain(d, governance_key_b64=gk, checkpoint=cp, history=hist, unpinned_signer=bool(allow_tls_directory))
                v["directory"] = {"epoch": res["epoch"], "root": res["root"], "chain_epochs": res["chain_epochs"], "checkpoint_epoch": cp["epoch"] if cp else None}
                v["trust_basis"] = "tls" if allow_tls_directory else "override" if (roots is not None or governance_key is not None) else "pinned-root"
                entry = next((k2 for k2 in res["keys"] if k2["public_key_b64"] == p["public_key_b64"]), None)
                if entry is None:
                    raise KernelError(C.KEY_NOT_LISTED, f"key {v['key']['kid']} is not in directory epoch {res['epoch']}")
                v["key"].update({"use": entry.get("use"), "status": entry.get("status"), "not_before": entry.get("not_before"), "not_after": entry.get("not_after"), "revoked_at": entry.get("revoked_at")})
                a = key_authorizes(entry, uses=spec["uses"], signed_time=p["signed_time"], now=now, anchor_time=anchor_time, skew=pol["skew"])
                v["key"]["evaluated_at"], v["key"]["time_basis"] = a["evaluated_at"], a["time_basis"]
                if not a["ok"]:
                    raise KernelError(a["code"], a["detail"])
                v["levels"]["trusted"] = True
        except Exception as e:  # noqa: BLE001
            reason("trusted", e)
        return finish()
    except Exception as e:  # noqa: BLE001
        reason("integrity", e)
        return finish()
