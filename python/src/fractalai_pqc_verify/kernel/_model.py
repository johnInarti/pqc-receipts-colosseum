"""Domain table, receipt kinds, key directory chain and key lifecycle — Python mirror of
kernel/src/{domains,kinds,directory,lifecycle}.mjs (spec/TRUST-KERNEL.md §4–§6). Same rules, same codes."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..jcs import canonicalize
from ._codes import C, KernelError, fail
from ._crypto import ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES, kid_for_key, mldsa_verify, sha256hex
from ._hygiene import MAX_SAFE, b64decode_strict, is_hex, is_num, is_safe_int, is_safe_uint, own

SERVED_PREFIX = "FRACTALAI-x402-served-v1"
KEY_DIR_DOMAIN = "FRACTALAI-key-directory-v1"
SELF_ATTEST_DOMAIN = "FRACTALAI-x402-self-attest-v1"
MIDAS_CANON_HEADER = "FRACTALAI-midas-alert-v1"
SEAL_SCHEMA = "fractalai.x402-settlement-seal/0.1"
USE_RECEIPT = "x402-receipt"
RESERVED_ROUTES = {"midas-alert": "midas-alert", "x402-witness": "x402-seal", "x402-attest-decision": "acp-verdict"}
ROUTE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")

KINDS = {
    "midas-alert": {"domain": f"{SERVED_PREFIX}\nmidas-alert", "uses": [USE_RECEIPT], "trust": "directory"},
    "x402-seal": {"domain": f"{SERVED_PREFIX}\nx402-witness", "uses": [USE_RECEIPT], "trust": "directory"},
    "acp-verdict": {"domain": f"{SERVED_PREFIX}\nx402-attest-decision", "uses": [USE_RECEIPT], "trust": "directory"},
    "served-proof": {"domain": SERVED_PREFIX, "uses": [USE_RECEIPT], "trust": "directory"},
    "self-attest-seal": {"domain": SELF_ATTEST_DOMAIN, "uses": [], "trust": "pinned-set-only"},
}

# ── canonicalisation of the SIGNED-JSON subset (safe integers only) ──
def canonicalize_signed(v) -> str:
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, bool) or x is None or isinstance(x, str):
            continue
        if is_num(x):
            if not is_safe_int(x):
                raise KernelError(C.SIGNED_JSON_NUMBER, f"signed JSON may only contain safe integers (got {x!r})")
            continue
        if isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, dict):
            stack.extend(x.values())
    return canonicalize(v)


def _jcs(v) -> str:
    try:
        return canonicalize(v)
    except (TypeError, ValueError) as e:
        raise KernelError(C.INPUT_SHAPE, str(e)) from None


# ── kinds ──
MIDAS_REQUIRED = ["address", "chain_id", "health_factor", "threshold", "collateral_usd", "debt_usd", "risk_tier", "observed_at", "source", "snapshot_hash", "emitted_at"]
ALWAYS_IGNORED = {"anchor", "anchors"}
MARKERS = {
    "midas-alert": ["canonical", "receipt_id", "served_message", "served_domain", "facts", "snapshot"],
    "x402-seal": ["body"], "self-attest-seal": ["body"], "acp-verdict": ["decision"], "served-proof": ["route_id", "digest"],
}
PROFILE_ALIAS = {"served-proof": "x402-served", "acp-verdict": "acp-verdict"}


def _key_and_sig(r):
    return {
        "pk": b64decode_strict(r.get("public_key"), ML_DSA_65_PK_BYTES, "public_key"),
        "sig": b64decode_strict(r.get("signature"), ML_DSA_65_SIG_BYTES, "signature"),
        "public_key_b64": r.get("public_key"),
    }


def _check_algorithm(r):
    if own(r, "algorithm") and r["algorithm"] != "ml-dsa-65":
        fail(C.ALGORITHM, f"algorithm {r['algorithm']!r} is not ml-dsa-65")


def parse_sealed_at(s) -> int:
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z", s):
        fail(C.SIGNED_TIME_MALFORMED, "sealed_at is not an RFC 3339 UTC timestamp")
    try:
        dt = datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        fail(C.SIGNED_TIME_MALFORMED, "sealed_at is not a real calendar time")
    return int(dt.timestamp())


def _dec_int(s, what) -> int:
    if not isinstance(s, str) or not re.fullmatch(r"0|[1-9][0-9]{0,15}", s):
        fail(C.CANONICAL_MALFORMED, f"{what} is not a canonical decimal integer")
    v = int(s)
    if v > MAX_SAFE:
        fail(C.CANONICAL_MALFORMED, f"{what} out of range")
    return v


def parse_midas_canonical(canonical) -> dict:
    if not isinstance(canonical, str) or canonical == "" or len(canonical) > 8192:
        fail(C.CANONICAL_MALFORMED, "canonical missing or too long")
    if "\r" in canonical or "\u0000" in canonical:
        fail(C.CANONICAL_MALFORMED, "canonical contains CR/NUL")
    header, *lines = canonical.split("\n")
    if header != MIDAS_CANON_HEADER:
        fail(C.CANONICAL_MALFORMED, f"canonical header is not {MIDAS_CANON_HEADER}")
    out: dict = {}
    for line in lines:
        # same character class as the JS reference's `.` (no line terminators: \n \r U+2028 U+2029)
        m = re.fullmatch("([a-z][a-z0-9_]{0,63})=([^\n\r\u2028\u2029]*)", line)
        if not m:
            fail(C.CANONICAL_MALFORMED, f"malformed canonical line {line[:40]!r}")
        if m.group(1) in out:
            fail(C.CANONICAL_MALFORMED, f"duplicate canonical key {m.group(1)}")
        out[m.group(1)] = m.group(2)
    for k in MIDAS_REQUIRED:
        if k not in out:
            fail(C.CANONICAL_MALFORMED, f"canonical lacks {k}")
    return out


def _fact_equals(v, s: str) -> bool:
    if isinstance(v, bool):
        return s == ("true" if v else "false")
    if isinstance(v, str):
        return v == s
    if v is None:
        return s == "null"
    if is_num(v):
        if not re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?", s):
            return False
        try:
            return float(s) == float(v)  # compared as IEEE-754 doubles (spec §4.2)
        except OverflowError:
            return False
    return False


def _midas(r):
    known = {"canonical", "signature", "public_key", "algorithm", "receipt_id", "served_message", "served_domain", "domain", "facts", "emitted_at", "content_id", "snapshot"}
    _check_algorithm(r)
    fields = parse_midas_canonical(r.get("canonical"))
    rid = sha256hex(r["canonical"])
    message = f"{SERVED_PREFIX}\nmidas-alert\n{rid}"
    if own(r, "receipt_id") and r["receipt_id"] != rid:
        fail(C.RECEIPT_ID_MISMATCH, "receipt_id != sha256(canonical)")
    if own(r, "content_id") and r["content_id"] != rid:
        fail(C.RECEIPT_ID_MISMATCH, "content_id != sha256(canonical)")
    if own(r, "served_message") and r["served_message"] != message:
        fail(C.SIGNED_MESSAGE_MISMATCH, "served_message != reconstructed signed message")
    if own(r, "served_domain") and r["served_domain"] != KINDS["midas-alert"]["domain"]:
        fail(C.DOMAIN_MISMATCH, "served_domain is not the midas-alert domain")
    if own(r, "domain") and r["domain"] not in (MIDAS_CANON_HEADER, KINDS["midas-alert"]["domain"]):
        fail(C.DOMAIN_MISMATCH, "domain is neither the canonical header nor the signed domain")
    signed_time = _dec_int(fields["emitted_at"], "emitted_at")
    if own(r, "emitted_at") and not (is_num(r["emitted_at"]) and r["emitted_at"] == signed_time):
        fail(C.UNSIGNED_FIELD_MISMATCH, f"top-level emitted_at {r['emitted_at']!r} != signed emitted_at {signed_time}")
    if own(r, "facts"):
        facts = r["facts"]
        if not isinstance(facts, dict):
            fail(C.UNSIGNED_FIELD_MISMATCH, "facts is not an object")
        bad = [k for k in facts if k not in fields or not _fact_equals(facts[k], fields[k])]
        bad += [k for k in fields if k not in facts]
        if bad:
            fail(C.UNSIGNED_FIELD_MISMATCH, "facts differ from the signed canonical: " + ", ".join(dict.fromkeys(bad)))
    signed = {"receipt_id": rid, "canonical_header": MIDAS_CANON_HEADER, **fields}
    if own(r, "snapshot"):
        if not is_hex(fields["snapshot_hash"], 64):
            fail(C.SNAPSHOT_MISMATCH, "signed snapshot_hash is not 64 hex")
        if sha256hex(_jcs(r["snapshot"])) != fields["snapshot_hash"]:
            fail(C.SNAPSHOT_MISMATCH, "sha256(JCS(snapshot)) != signed snapshot_hash")
        signed["snapshot"] = r["snapshot"]
    return {"kind": "midas-alert", "content_id": rid, "message": message, **_key_and_sig(r), "signed_time": signed_time,
            "signed": signed, "ignored": [k for k in r if k not in known and k not in ALWAYS_IGNORED]}


def _seal_like(r, kind):
    known = {"algorithm", "domain", "content_id", "public_key", "signature", "body"}
    _check_algorithm(r)
    if r.get("domain") != KINDS[kind]["domain"]:
        fail(C.DOMAIN_MISMATCH, f"seal domain is not the {kind} domain")
    body = r.get("body")
    if not isinstance(body, dict):
        fail(C.INPUT_SHAPE, "seal body missing or not an object")
    if body.get("schema") != SEAL_SCHEMA:
        fail(C.SCHEMA_MISMATCH, f"body.schema is not {SEAL_SCHEMA}")
    cid = sha256hex(canonicalize_signed(body))
    if r.get("content_id") != cid:
        fail(C.CONTENT_ID_MISMATCH, "content_id != sha256(JCS(body)) — body altered")
    if "sealed_at" not in body:
        fail(C.SIGNED_TIME_MALFORMED, "body.sealed_at missing")
    signed_time = parse_sealed_at(body["sealed_at"])
    return {"kind": kind, "content_id": cid, "message": f"{KINDS[kind]['domain']}\n{cid}", **_key_and_sig(r), "signed_time": signed_time,
            "signed": {"content_id": cid, **body}, "ignored": [k for k in r if k not in known and k not in ALWAYS_IGNORED]}


def _acp(r):
    known = {"decision", "signed_message", "signature", "public_key", "profile", "algorithm"}
    _check_algorithm(r)
    if not isinstance(r.get("decision"), dict):
        fail(C.INPUT_SHAPE, "acp-verdict needs a decision object")
    digest = sha256hex(canonicalize_signed(r["decision"]))
    message = f"{SERVED_PREFIX}\nx402-attest-decision\n{digest}"
    if own(r, "signed_message") and r["signed_message"] != message:
        fail(C.SIGNED_MESSAGE_MISMATCH, "signed_message != served proof over sha256(JCS(decision))")
    return {"kind": "acp-verdict", "content_id": digest, "message": message, **_key_and_sig(r), "signed_time": None,
            "signed": {"digest": digest, **r["decision"]}, "ignored": [k for k in r if k not in known]}


def _served(r):
    known = {"domain", "route_id", "digest", "signed_message", "signature", "public_key", "profile", "algorithm"}
    _check_algorithm(r)
    if r.get("domain") != SERVED_PREFIX:
        fail(C.DOMAIN_MISMATCH, f"served-proof domain is not {SERVED_PREFIX}")
    route = r.get("route_id")
    if not isinstance(route, str) or not ROUTE_RE.fullmatch(route):
        fail(C.ROUTE_MALFORMED, "route_id must match ^[a-z0-9][a-z0-9-]{0,63}$")
    if route in RESERVED_ROUTES:
        fail(C.ROUTE_RESERVED, f"route {route!r} is reserved for kind {RESERVED_ROUTES[route]}")
    if not is_hex(r.get("digest"), 64):
        fail(C.DIGEST_MALFORMED, "digest must be 64 lowercase hex")
    message = f"{SERVED_PREFIX}\n{route}\n{r['digest']}"
    if own(r, "signed_message") and r["signed_message"] != message:
        fail(C.SIGNED_MESSAGE_MISMATCH, "signed_message != domain\\nroute\\ndigest")
    return {"kind": "served-proof", "content_id": r["digest"], "message": message, **_key_and_sig(r), "signed_time": None,
            "signed": {"route_id": route, "digest": r["digest"]}, "ignored": [k for k in r if k not in known]}


PARSERS = {"midas-alert": _midas, "x402-seal": lambda r: _seal_like(r, "x402-seal"), "self-attest-seal": lambda r: _seal_like(r, "self-attest-seal"), "acp-verdict": _acp, "served-proof": _served}


def infer_kind(r) -> str:
    if not isinstance(r, dict):
        fail(C.INPUT_SHAPE, "receipt is not a JSON object")
    if "canonical" in r:
        return "midas-alert"
    if "body" in r:
        return "self-attest-seal" if r.get("domain") == SELF_ATTEST_DOMAIN else "x402-seal"
    if "decision" in r:
        return "acp-verdict"
    if "route_id" in r:
        return "served-proof"
    fail(C.KIND_UNKNOWN, "cannot determine the receipt kind from its shape")


def check_unambiguous(r, kind):
    fam = lambda k: "x402-seal" if k == "self-attest-seal" else k  # noqa: E731
    families = {fam(k) for k, fields in MARKERS.items() if any(f in r for f in fields)}
    for f in families:
        if f != fam(kind):
            fail(C.KIND_AMBIGUOUS, f"document carries {f} fields while being verified as {kind}")
    if "profile" in r and r["profile"] != PROFILE_ALIAS.get(kind, kind):
        fail(C.KIND_AMBIGUOUS, f"profile does not name kind {kind}")


def parse_receipt(r, kind=None):
    if not isinstance(r, dict):
        fail(C.INPUT_SHAPE, "receipt is not a JSON object")
    kind = kind or infer_kind(r)
    if kind not in PARSERS:
        fail(C.KIND_UNKNOWN, f"unknown kind {kind!r}")
    check_unambiguous(r, kind)
    return PARSERS[kind](r)


def anchor_ids(p) -> dict:
    return {"receipt_id": sha256hex(p["sig"]), "payload_hash": sha256hex(p["message"]), "kid16": sha256hex(p["public_key_b64"])[:16]}


# ── key directory ──
ZERO_ROOT = "0" * 64
STATUSES = ("reserved", "active", "retiring", "retired", "revoked")
TRANSITIONS = {"reserved": ("reserved", "active", "revoked"), "active": ("active", "retiring", "retired", "revoked"),
               "retiring": ("retiring", "retired", "revoked"), "retired": ("retired", "revoked"), "revoked": ("revoked",)}


def directory_root(keys, prev_root, epoch, governance_key_b64) -> str:
    ks = sorted(keys, key=lambda k: k["kid"].encode("utf-16-be", "surrogatepass"))
    return sha256hex(_jcs({"epoch": epoch, "prev_root": prev_root or ZERO_ROOT, "governance_key": governance_key_b64 or None, "keys": ks}))


def _d(detail):
    return KernelError(C.DIRECTORY_INVALID, detail)


def check_epoch(d, governance_key_b64=None):
    if not isinstance(d, dict):
        raise _d("directory is not an object")
    if d.get("spec") != KEY_DIR_DOMAIN:
        raise _d(f"spec is not {KEY_DIR_DOMAIN}")
    if not (is_safe_int(d.get("epoch")) and d["epoch"] >= 1):
        raise _d("epoch is not a positive integer")
    if not is_hex(d.get("root"), 64):
        raise _d("root is not 64 lowercase hex")
    if own(d, "prev_root") and d["prev_root"] is not None and not is_hex(d["prev_root"], 64):
        raise _d("prev_root is not 64 lowercase hex")
    if d["epoch"] == 1 and (d.get("prev_root") or ZERO_ROOT) != ZERO_ROOT:
        raise _d("epoch 1 must have a zero prev_root")
    keys = d.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 256:
        raise _d("keys[] missing, empty or > 256")

    def as_dir(fn):
        try:
            return fn()
        except KernelError as e:
            raise _d(e.detail) from None

    pk = as_dir(lambda: b64decode_strict(d.get("directory_public_key"), ML_DSA_65_PK_BYTES, "directory_public_key"))
    sig = as_dir(lambda: b64decode_strict(d.get("signature"), ML_DSA_65_SIG_BYTES, "directory signature"))
    kids, pks = set(), set()
    for k in keys:
        if not isinstance(k, dict):
            raise _d("key entry is not an object")
        if not isinstance(k.get("public_key_b64"), str):
            raise _d("key entry without public_key_b64")
        as_dir(lambda: b64decode_strict(k["public_key_b64"], ML_DSA_65_PK_BYTES, "public_key_b64"))
        if k.get("kid") != kid_for_key(k["public_key_b64"]):
            raise _d("kid != sha256(public_key_b64)[:16] (aliased kid)")
        if k["kid"] in kids or k["public_key_b64"] in pks:
            raise _d(f"key {k['kid']} listed more than once (ambiguous status)")
        kids.add(k["kid"]); pks.add(k["public_key_b64"])
        if not isinstance(k.get("use"), str):
            raise _d(f"key {k['kid']} has no use")
        if k.get("status") not in STATUSES:
            raise _d(f"key {k['kid']} status {k.get('status')!r} is not allowed")
        for f in ("not_before", "not_after", "revoked_at", "added_at"):
            if own(k, f) and k[f] is not None and not is_safe_uint(k[f]):
                raise _d(f"key {k['kid']} {f} must be a non-negative integer or null")
    if d["directory_public_key"] in pks:
        raise _d("governance key is also listed as a receipt key (use separation violated)")
    if directory_root(keys, d.get("prev_root"), d["epoch"], d["directory_public_key"]) != d["root"]:
        raise _d("root does not recompute over {epoch, prev_root, governance_key, keys}")
    message = f"{KEY_DIR_DOMAIN}\n{d['root']}"
    if own(d, "signed_message") and d["signed_message"] != message:
        raise _d('signed_message != "FRACTALAI-key-directory-v1\\n" + root')
    if not mldsa_verify(sig, message.encode("utf-8"), pk):
        raise _d("governance ML-DSA-65 signature does not verify")
    if governance_key_b64 is not None and d["directory_public_key"] != governance_key_b64:
        raise KernelError(C.DIRECTORY_SIGNER_NOT_PINNED, "directory is signed by a key that is not the pinned governance key")
    return d


def _append_only(prev, nxt):
    by = {k["kid"]: k for k in nxt["keys"]}
    for a in prev["keys"]:
        b = by.get(a["kid"])
        if b is None:
            fail(C.DIRECTORY_NOT_APPEND_ONLY, f"epoch {nxt['epoch']} removed key {a['kid']}")
        if b["public_key_b64"] != a["public_key_b64"] or b.get("use") != a.get("use"):
            fail(C.DIRECTORY_NOT_APPEND_ONLY, f"epoch {nxt['epoch']} rebound key {a['kid']}")
        if b["status"] not in TRANSITIONS[a["status"]]:
            fail(C.DIRECTORY_NOT_APPEND_ONLY, f"key {a['kid']}: status {a['status']} -> {b['status']} not allowed")
        if a.get("not_before") is not None and b.get("not_before") != a["not_before"]:
            fail(C.DIRECTORY_NOT_APPEND_ONLY, f"key {a['kid']}: not_before changed")
        if a.get("revoked_at") is not None and b.get("revoked_at") != a["revoked_at"]:
            fail(C.DIRECTORY_NOT_APPEND_ONLY, f"key {a['kid']}: revoked_at changed")
        if a.get("not_after") is not None and b.get("not_after") is not None and b["not_after"] > a["not_after"]:
            fail(C.DIRECTORY_NOT_APPEND_ONLY, f"key {a['kid']}: not_after extended")


def verify_directory_chain(d, *, governance_key_b64, checkpoint, history=(), unpinned_signer=False):
    gk = None if unpinned_signer else governance_key_b64
    if not unpinned_signer and not isinstance(gk, str):
        fail(C.NO_TRUST_SOURCE, "no pinned governance key")
    check_epoch(d, gk)
    signer = d["directory_public_key"]
    res = lambda chain: {"epoch": d["epoch"], "root": d["root"], "keys": d["keys"], "chain_epochs": chain}  # noqa: E731
    if not checkpoint:
        return res([d["epoch"]])
    if d["epoch"] < checkpoint["epoch"]:
        fail(C.DIRECTORY_ROLLBACK, f"directory epoch {d['epoch']} < pinned checkpoint epoch {checkpoint['epoch']}")
    if d["epoch"] == checkpoint["epoch"]:
        if d["root"] != checkpoint["root"]:
            fail(C.DIRECTORY_EQUIVOCATION, f"epoch {d['epoch']} root != pinned checkpoint root")
        return res([d["epoch"]])
    by_epoch: dict = {}
    for h in history or ():
        if not isinstance(h, dict) or not is_safe_int(h.get("epoch")):
            fail(C.DIRECTORY_INVALID, "history entry is not a directory")
        if h["epoch"] <= checkpoint["epoch"] or h["epoch"] >= d["epoch"]:
            continue
        if h["epoch"] in by_epoch and by_epoch[h["epoch"]].get("root") != h.get("root"):
            fail(C.DIRECTORY_EQUIVOCATION, f"two different roots supplied for epoch {h['epoch']}")
        by_epoch[h["epoch"]] = h
    prev_root = checkpoint["root"]
    prev_dir = None
    cp_body = checkpoint.get("directory") or next((h for h in history or () if isinstance(h, dict) and h.get("epoch") == checkpoint["epoch"]), None)
    if cp_body:
        check_epoch(cp_body, gk)
        if cp_body["root"] != checkpoint["root"]:
            fail(C.DIRECTORY_EQUIVOCATION, "supplied checkpoint body does not match the pinned root")
        prev_dir = cp_body
    chain = [checkpoint["epoch"]]
    for e in range(checkpoint["epoch"] + 1, d["epoch"] + 1):
        cur = d if e == d["epoch"] else by_epoch.get(e)
        if cur is None:
            fail(C.DIRECTORY_CHAIN_GAP, f"epoch {e} missing between pinned checkpoint {checkpoint['epoch']} and {d['epoch']}")
        if cur is not d:
            check_epoch(cur, gk)
        if cur["directory_public_key"] != signer:
            fail(C.DIRECTORY_SIGNER_NOT_PINNED, f"epoch {e} signed by a different governance key")
        if (cur.get("prev_root") or ZERO_ROOT) != prev_root:
            fail(C.DIRECTORY_CHAIN_BREAK, f"epoch {e} prev_root does not equal epoch {e - 1} root")
        if prev_dir:
            _append_only(prev_dir, cur)
        prev_root, prev_dir = cur["root"], cur
        chain.append(e)
    return res(chain)


# ── lifecycle (spec §6.3) ──
def key_authorizes(key, *, uses, signed_time, now, anchor_time, skew):
    basis = "verification-time" if signed_time is None else "signed"
    t = now if signed_time is None else signed_time
    r = lambda ok, code, detail, b=basis: {"ok": ok, "code": code, "detail": detail, "evaluated_at": t, "time_basis": b}  # noqa: E731
    if key.get("use") not in uses:
        return r(False, C.KEY_USE_MISMATCH, f"key use {key.get('use')!r} does not authorize this kind")
    if signed_time is not None and signed_time > now + skew:
        return r(False, C.SIGNED_TIME_IN_FUTURE, f"signed time {signed_time} is after verification time {now}")
    nb, na, st = key.get("not_before"), key.get("not_after"), key.get("status")
    if st == "reserved":
        return r(False, C.KEY_STATUS_RESERVED, "key is reserved (never activated)")
    if st == "active":
        if nb is None:
            return r(False, C.KEY_WINDOW_MALFORMED, "active key without not_before")
        if t < nb:
            return r(False, C.KEY_NOT_YET_VALID, f"T={t} < not_before {nb}")
        if na is not None and t > na:
            return r(False, C.KEY_EXPIRED, f"T={t} > not_after {na}")
        return r(True, None, "active key inside its window")
    if st in ("retiring", "retired"):
        if signed_time is None:
            return r(False, C.KEY_NEEDS_SIGNED_TIME, f"a {st} key only authorizes receipts that carry a signed time")
        if nb is None or na is None:
            return r(False, C.KEY_WINDOW_MALFORMED, f"{st} key without not_before/not_after")
        if t < nb:
            return r(False, C.KEY_NOT_YET_VALID, f"T={t} < not_before {nb}")
        if t > na:
            return r(False, C.KEY_EXPIRED, f"T={t} > not_after {na}")
        return r(True, None, f"{st} key, signed time inside its window")
    if st == "revoked":
        ra = key.get("revoked_at")
        if ra is None:
            return r(False, C.KEY_REVOKED, "key revoked without revoked_at")
        if signed_time is None:
            return r(False, C.KEY_REVOKED, "revoked key and the kind signs no time")
        if anchor_time is None:
            return r(False, C.KEY_REVOKED, f"key revoked at {ra}; needs a consensus time anchor before {ra}")
        if anchor_time >= ra:
            return r(False, C.KEY_REVOKED, f"earliest anchor {anchor_time} is not before revocation {ra}")
        if nb is None or t < nb:
            return r(False, C.KEY_NOT_YET_VALID, f"T={t} < not_before {nb}")
        if na is not None and t > na:
            return r(False, C.KEY_EXPIRED, f"T={t} > not_after {na}")
        if t > anchor_time + skew:
            return r(False, C.ANCHOR_FORWARD_DATED, f"signed time {t} after anchor {anchor_time}")
        return {"ok": True, "code": None, "detail": "revoked, but anchored before revocation", "evaluated_at": anchor_time, "time_basis": "anchor"}
    return r(False, C.KEY_STATUS_UNKNOWN, f"unknown status {st!r}")
