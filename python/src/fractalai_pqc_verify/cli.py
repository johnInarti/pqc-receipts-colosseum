"""``fractalai-verify`` command line.

    fractalai-verify midas [RECEIPT_ID]          fetch a public MIDAS alert receipt + key directory, verify
    fractalai-verify receipt FILE [--key B64 ...] [--directory URL_OR_FILE] [--governance-key B64]
    fractalai-verify directory [URL_OR_FILE] [--governance-key B64] [--anchored-root HEX]
    fractalai-verify conformance [VECTORS_DIR]   run the 7 golden vectors (bundled by default)

Exit code 0 only when the verdict is VALID / CONFORMANT.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .conformance import missing_profiles, run_conformance
from .directory import DEFAULT_DIRECTORY_URL, KeyDirectory, KeyDirectoryError, fetch_key_directory, load_key_directory
from .mldsa import backend_name
from .receipt import DEFAULT_BASE_URL, fetch_midas_receipt, verify_receipt

PUBLIC_RECEIPT = "fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee"


def _directory(src: str, args: argparse.Namespace) -> KeyDirectory:
    kw = dict(
        governance_key=getattr(args, "governance_key", None),
        anchored_root=getattr(args, "anchored_root", None),
        require_authenticated=getattr(args, "require_authenticated", False),
    )
    if src.startswith("https://"):
        return fetch_key_directory(src, **kw)
    return load_key_directory(src, **kw)


def _emitted_at(receipt) -> int | None:
    # a 'retiring' key is acceptable for receipts emitted before its not_after
    try:
        return int(receipt.get("emitted_at"))
    except (TypeError, ValueError, AttributeError):
        return None


def _print_result(result, directory: KeyDirectory | None) -> int:
    out = result.to_dict()
    if out.get("public_key"):
        out["public_key"] = out["public_key"][:24] + "…"
    if directory is not None:
        out["directory"] = {
            "source": directory.source,
            "epoch": directory.epoch,
            "root": directory.root,
            "trust_basis": directory.trust_basis,
            "key_status": directory.status_of(result.public_key) if result.public_key else None,
        }
    out["backend"] = backend_name()
    print(json.dumps(out, indent=2, ensure_ascii=False))
    print("VALID (signature verified; key trusted)" if result.valid else f"INVALID: {result.reason}")
    return 0 if result.valid else 1


def _cmd_midas(args) -> int:
    receipt = fetch_midas_receipt(args.receipt_id, args.base_url)
    directory = _directory(args.directory, args)
    trusted = directory.trusted_keys(include_retiring=args.include_retiring, now=_emitted_at(receipt))
    return _print_result(verify_receipt(receipt, trusted), directory)


def _cmd_receipt(args) -> int:
    with open(args.file, encoding="utf-8") as f:
        receipt = json.load(f)
    trusted: list[str] | None = list(args.key) if args.key else None
    directory = None
    if args.directory:
        directory = _directory(args.directory, args)
        trusted = (trusted or []) + directory.trusted_keys(include_retiring=args.include_retiring, now=_emitted_at(receipt))
    route = None if args.any_route else args.route
    return _print_result(verify_receipt(receipt, trusted, expected_route=route), directory)


def _cmd_directory(args) -> int:
    d = _directory(args.source, args)
    print(json.dumps({
        "source": d.source, "epoch": d.epoch, "root": d.root, "prev_root": d.raw.get("prev_root"),
        "trust_basis": d.trust_basis, "authenticated": d.verification.valid, "reason": d.verification.reason,
        "governance_key": d.governance_key,
        "keys": [{"kid": k.get("kid"), "status": k.get("status"), "not_after": k.get("not_after")} for k in d.keys],
        "trusted_now": len(d.trusted_keys()),
    }, indent=2))
    print(f"DIRECTORY OK (integrity verified; trust basis: {d.trust_basis})")
    return 0


def _cmd_conformance(args) -> int:
    rows = run_conformance(args.vectors_dir)
    yn = lambda b: "PASS" if b else "FAIL"  # noqa: E731
    print(f"\nPQC Agent-Receipt Conformance (Python, backend={backend_name()}) — ML-DSA-65 (FIPS 204), offline, FAIL-CLOSED\n")
    print(f"{'profile':<24}{'authentic':<11}{'fail-closed':<13}{'tamper✗':<9}{'forgery✗':<10}result")
    print("-" * 78)
    for r in rows:
        print(f"{r.profile:<24}{yn(r.genuine):<11}{yn(r.fail_closed):<13}{yn(r.tamper_rejected):<9}{yn(r.forge_rejected):<10}{'OK' if r.ok else 'FAIL'}")
    miss = missing_profiles(rows)
    if miss:
        print(f"\nprofiles with no vector present: {', '.join(miss)}")
    ok = bool(rows) and all(r.ok for r in rows)
    print(f"\n{'CONFORMANT' if ok else 'NON-CONFORMANT'} — {sum(r.ok for r in rows)}/{len(rows)} profiles")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fractalai-verify", description="Offline verifier for FractalAI ML-DSA-65 (FIPS 204) receipts.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def trust_opts(sp, default_dir: str | None):
        sp.add_argument("--directory", default=default_dir, help="key directory URL (https) or saved JSON file")
        sp.add_argument("--governance-key", help="pin the directory governance public key (base64)")
        sp.add_argument("--anchored-root", help="require the directory root to equal this on-chain anchored root")
        sp.add_argument("--require-authenticated", action="store_true", help="refuse a directory trusted only via TLS")
        sp.add_argument("--include-retiring", action="store_true", help="also trust 'retiring' keys until not_after")

    m = sub.add_parser("midas", help="fetch + verify a public MIDAS signed alert (network for fetching only)")
    m.add_argument("receipt_id", nargs="?", default=PUBLIC_RECEIPT)
    m.add_argument("--base-url", default=DEFAULT_BASE_URL)
    trust_opts(m, DEFAULT_DIRECTORY_URL)
    m.set_defaults(func=_cmd_midas)

    r = sub.add_parser("receipt", help="verify a receipt JSON file offline")
    r.add_argument("file")
    r.add_argument("--key", action="append", help="trusted ML-DSA-65 public key (base64); repeatable")
    r.add_argument("--route", default="midas-alert", help="expected served route (default: midas-alert)")
    r.add_argument("--any-route", action="store_true", help="accept the route named in served_message")
    trust_opts(r, None)
    r.set_defaults(func=_cmd_receipt)

    d = sub.add_parser("directory", help="fetch/load and verify the key directory")
    d.add_argument("source", nargs="?", default=DEFAULT_DIRECTORY_URL)
    d.add_argument("--governance-key")
    d.add_argument("--anchored-root")
    d.add_argument("--require-authenticated", action="store_true")
    d.set_defaults(func=_cmd_directory)

    c = sub.add_parser("conformance", help="run the golden conformance vectors")
    c.add_argument("vectors_dir", nargs="?", default=None)
    c.set_defaults(func=_cmd_conformance)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyDirectoryError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
