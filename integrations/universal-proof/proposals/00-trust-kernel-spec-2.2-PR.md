# DRAFT PR body — johnInarti/pqc-receipts-colosseum (not opened)

**Branch:** `feat/agent-commerce-receipt` (apply `kernel-patch/0001-kind-agent-commerce-receipt.patch` on `b51ed02`, then run `node corpus/gen.mjs`)

## Trust Kernel spec 2.2 — kind `agent-commerce-receipt` (purely additive)

Adds one protocol-neutral kind that binds three things under one ML-DSA-65 signature and one signed time:

- payment identifiers;
- hashes of a payment protocol's own artifacts (AP2 receipts and mandates, ERC-8004 requests, MCP tool calls, PIX/SPEI ids);
- the sha256 of the delivered content.

- Own domain `FRACTALAI-agent-commerce-receipt-v1` and own key use `commerce-receipt`. Domain and use separation keeps
  it apart from x402, MIDAS and stablecoin receipts in both directions.
- Closed body: `v, protocol, profile, issued_at, payment, bindings, delivery`. Every string is printable ASCII and every
  number is a safe integer, so JCS is identical across runtimes (A8). The body is limited to 8 KiB.
- The kernel checks shape, signature, key trust and lifecycle, and time. It never interprets `payment` or `bindings`;
  profile semantics are re-derived by adapters (spec §13.4).
- JS kernel and Python port. 44 new corpus vectors: 6 positive (including one anchored on a synthetic Arbitrum node
  with the real runtime code) and 38 negative (shape, unsigned copies, kind ambiguity, cross-domain replay, key
  use, lifecycle, anchor `observedAt`). **Both implementations pass 217/217**, and the pre-existing 173 vectors are
  byte-identical.
- Honest limit asserted by a vector: production epoch 3 has no `commerce-receipt` key
  (`N-AC-production-directory-has-no-commerce-key`).

Adapters that use it (AP2 v0.2 over A2A v1, MCP, ERC-8004) live in the FractalAI monorepo
`integrations/universal-proof/` and are tested against the official AP2 SDK, the official MCP TS SDK and the official
ERC-8004 contracts.

Authored by John Edward Romo Sanchez; drafted with AI assistance (Claude). Internal review only; no external audit.
