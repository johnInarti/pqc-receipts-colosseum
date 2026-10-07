"""Corpus runner — Python consumer of corpus/ (format fractalai.trust-corpus/1, see corpus/README.md).

    python -m fractalai_pqc_verify.kernel.corpus <path/to/corpus> [--only ID]

Refuses an empty corpus or a manifest mismatch; exit 0 only if 100 % of the vectors pass.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

from ..jcs import canonicalize
from ._hygiene import parse_json_strict
from ._verify import verify

LEVELS = ("integrity", "authentic", "trusted", "time_anchored", "finalized")


def _resolve(v, root: Path, cache: dict):
    if isinstance(v, list):
        out = []
        for x in v:
            r = _resolve(x, root, cache)
            if isinstance(x, dict) and isinstance(x.get("$ref"), str) and "#" in x["$ref"] and isinstance(r, list):
                out.extend(r)
            else:
                out.append(r)
        return out
    if isinstance(v, dict):
        if isinstance(v.get("$ref"), str):
            f, _, frag = v["$ref"].partition("#")
            if not f.startswith("fixtures/") or ".." in f or not f.endswith(".json"):
                raise ValueError(f"bad $ref {v['$ref']}")
            if f not in cache:
                cache[f] = parse_json_strict((root / f).read_text("utf-8"))
            doc = cache[f]
            return copy.deepcopy(doc[frag] if frag else doc)
        return {k: _resolve(x, root, cache) for k, x in v.items()}
    return v


def replay_transport(transcript):
    table = {}
    for t in transcript or []:
        table[(t["url"], t["method"], canonicalize(t.get("params", [])))] = t

    def transport(url, body):
        req = json.loads(body)
        hit = table.get((url, req["method"], canonicalize(req.get("params", []))))
        if hit is None:
            return json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32601, "message": f"not in transcript: {req['method']}"}})
        if "error" in hit:
            return json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": hit["error"]})
        return json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": hit["result"]})

    return transport


def kernel_kwargs(ctx):
    o = dict(ctx.get("options") or {})
    kw = {"now": ctx.get("now")}
    for k, x in o.items():
        if x is None:
            continue
        kw[k] = json.dumps(x) if k in ("anchors", "trusted_keys") else x
    if "roots" in ctx:
        kw["roots"] = ctx["roots"]
    if "directory" in ctx:
        kw["directory"] = json.dumps(ctx["directory"])
    if "directory_history" in ctx:
        kw["directory_history"] = json.dumps(ctx["directory_history"])
    kw["transport"] = replay_transport(ctx.get("rpc_transcript"))
    return kw


def compare(v, expect):
    errs = []
    if v["valid"] != expect["valid"]:
        errs.append(f"valid {v['valid']} != {expect['valid']}")
    for lv in LEVELS:
        if v["levels"][lv] != expect["levels"][lv]:
            errs.append(f"{lv} {v['levels'][lv]} != {expect['levels'][lv]}")
    if "trust_basis" in expect and v["trust_basis"] != expect["trust_basis"]:
        errs.append(f"trust_basis {v['trust_basis']} != {expect['trust_basis']}")
    if "exit_code" in expect and v["exit_code"] != expect["exit_code"]:
        errs.append(f"exit_code {v['exit_code']} != {expect['exit_code']}")
    got = {r["code"] for r in v["reasons"]}
    errs += [f"missing reason code {c}" for c in expect.get("codes", []) if c not in got]
    if expect["valid"] is False and not v["reasons"]:
        errs.append("invalid verdict without any reason")
    return errs


def run(root: Path, only: str | None = None):
    manifest = parse_json_strict((root / "manifest.json").read_text("utf-8"))
    ids = sorted((manifest.get("vectors") or {}).keys())
    files = sorted(p.stem for p in (root / "vectors").glob("*.json"))
    if not ids or manifest.get("count") != len(ids) or set(files) != set(ids):
        raise SystemExit("corpus runner refused: empty corpus or manifest/vectors mismatch")
    passed, fails, cache = 0, [], {}
    for vid in ids:
        if only and vid != only:
            continue
        raw = (root / "vectors" / f"{vid}.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest["vectors"][vid]:
            fails.append((vid, ["vector file hash != manifest"], None))
            continue
        vec = _resolve(parse_json_strict(raw.decode("utf-8")), root, cache)
        for p in vec["input"].get("prime_json", []):
            try:
                json.loads(p)
            except ValueError:
                pass
        inp = vec["input"]["receipt_text"] if "receipt_text" in vec["input"] else json.dumps(vec["input"]["receipt"])
        try:
            v = verify(inp, **kernel_kwargs(vec["context"]))
        except Exception as e:  # noqa: BLE001 — the kernel must never raise
            fails.append((vid, [f"kernel raised {type(e).__name__}: {e}"], None))
            continue
        errs = compare(v, vec["expect"])
        if errs:
            fails.append((vid, errs, v["reasons"]))
        else:
            passed += 1
    return passed, fails, (1 if only else len(ids))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    only = argv[argv.index("--only") + 1] if "--only" in argv else None
    root = Path(next((a for a in argv if not a.startswith("--") and a != only), "corpus"))
    passed, fails, total = run(root, only)
    for vid, errs, reasons in fails:
        print(f"FAIL {vid}: {'; '.join(errs)}" + (f"\n     reasons: {json.dumps(reasons)[:400]}" if reasons else ""))
    print(f"corpus (python): {passed}/{total} vectors pass")
    return 0 if not fails and passed == total and total > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
