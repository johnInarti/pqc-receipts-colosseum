#!/usr/bin/env bash
# Reproducible Trust Kernel v2 + spec 2.2 (kind agent-commerce-receipt) for the adapters in this package.
#
#   1. clone the PUBLIC kernel repo at the pinned upstream commit into ./.kernel (gitignored)
#   2. apply kernel-patch/0001-kind-agent-commerce-receipt.patch (kernel JS, Python port, spec §13, corpus generator)
#   3. regenerate the corpus deterministically and check the manifest hash recorded below
#   4. run the corpus (JS) — expected 217/217
#
# No secrets, no network writes: read-only git clone + npm ci from the public registry.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
UPSTREAM="https://github.com/johnInarti/pqc-receipts-colosseum"
BASE_COMMIT="b51ed02"
EXPECTED_MANIFEST_SHA256="95b027dcf4cb3f49ce65876f4979fcc4eed97f25cec3d0dfad5b728f5decb8f5"
DEST="$HERE/.kernel"

if [ ! -d "$DEST/.git" ]; then
  git clone --quiet "$UPSTREAM" "$DEST"
fi
cd "$DEST"
git checkout --quiet "$BASE_COMMIT"
git checkout --quiet -B agent-commerce-receipt
if ! grep -q "agent-commerce-receipt" kernel/src/domains.mjs; then
  git apply --whitespace=nowarn "$HERE/kernel-patch/0001-kind-agent-commerce-receipt.patch"
fi
for d in kernel corpus issuer; do (cd "$d" && npm ci --no-audit --no-fund --silent); done
(cd corpus && node gen.mjs)
GOT="$(shasum -a 256 corpus/manifest.json | cut -d' ' -f1)"
if [ "$GOT" != "$EXPECTED_MANIFEST_SHA256" ]; then
  echo "corpus manifest sha256 $GOT != expected $EXPECTED_MANIFEST_SHA256 (non-deterministic generation?)" >&2
  exit 1
fi
(cd corpus && node run.mjs)
