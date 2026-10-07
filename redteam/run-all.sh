#!/usr/bin/env bash
# Runs every red-team PoC from the 2026-10-06 reviews against THIS tree (Trust Kernel v2).
# Node PoCs (poc1..poc8) are the ORIGINAL files, unmodified, except poc7: its informational JCS sweep printed
# jcs('\ud800') and now that call throws (lone surrogates are refused by design), so the harness wraps that
# single expression in a try/catch in a temporary copy. Each PoC prints VULNERABLE / OK and exits 1 if any
# attack still works. Anchor (RT-E*/RT-S*), Action (RT-*) and Python (F*/N*) PoCs are encoded as golden
# vectors in corpus/ (node corpus/run.mjs) and in the anchor red-team's own scripts (see README).
set -u
cd "$(dirname "$0")"
ln -sfn ../verifier/node_modules node_modules; ln -sfn ../deployments deployments
ln -sfn ../../verifier/src anchor/src; ln -sfn ../../verifier/node_modules anchor/node_modules
fail=0
for f in poc1-*.mjs poc2-*.mjs poc3-*.mjs poc4-*.mjs poc5-*.mjs poc6-*.mjs poc8-*.mjs; do
  node "$f" || fail=1
done
tmp=$(mktemp ./tmp-poc7-XXXX.mjs)
sed "s/jcsW('\\\\ud800')/(() => { try { return jcsW('\\\\ud800'); } catch (e) { return 'REFUSED ' + e.code; } })()/" poc7-canon-and-misc.mjs > "$tmp"
node "$tmp" || fail=1
rm -f "$tmp"
rm -rf tmp-empty-* tmp-one-*
echo "--- anchor red-team runner (ACCEPTED = control or attack works) ---"
(cd anchor && node redteam-poc.mjs --src ./src) || fail=1
echo "--- python red-team (needs fractalai-pqc-verify installed) ---"
python3 python-poc.py || true
exit $fail
