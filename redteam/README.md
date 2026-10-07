# Red-team PoCs replayed against Trust Kernel v2

`./run-all.sh` replays the 2026-10-06 proofs of concept against this tree.

| Source | Where | Result on Trust Kernel v2 |
|---|---|---|
| Node verifier/conformance red-team (poc1–poc8) | `poc*.mjs` (original files, unmodified; poc7 runs through a one-expression try/catch because `jcs('\ud800')` now throws by design) | all `OK (not vulnerable)` |
| Anchor red-team runner | `anchor/redteam-poc.mjs --src ./src` | controls (genuine devnet memo, real Arc anchor) ACCEPTED; RT-S2/S3/S5/E5 REFUSED |
| Anchor red-team unit suite | `anchor/test/redteam-anchors.test.mjs` | no attack accepted; 13 assertions fail only on old message wording or on the stricter rule "an unsigned key directory is never trusted" (RT-E8/E9 used unsigned directories) |
| Anchor red-team, real EVM | `anchor/PQCReceiptAnchor.kernel-e2e.test.js` (Hardhat, real bytecode = mainnet code hash) | 5/5: genuine VALID; look-alike, pinned look-alike, squat, front-run observedAt REFUSED |
| Python differential red-team (F1–F11) | `python-poc.py` | 0/13 attacks work |
| GitHub Action red-team (RT-5/8/9/11/12/13) | encoded as corpus vectors | all refused |

Every PoC is also a golden negative vector in `../corpus/vectors` (`source` field), which both the JS kernel and
the Python port must pass at 100 %.
