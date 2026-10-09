# @fractalai/pqc-trust-kernel — Trust Kernel v2

The single reference implementation of FractalAI's receipt-trust decision (spec: [`../spec/TRUST-KERNEL.md`](../spec/TRUST-KERNEL.md)).
Pure ESM, dependencies: `@noble/post-quantum`, `@noble/hashes`, `@noble/curves`. Node ≥ 20.

```js
import { verify } from '@fractalai/pqc-trust-kernel';
const v = await verify(receiptJsonText, { kind: 'midas-alert', directory: directoryJsonText });
v.valid;        // policy-required levels all true (default: integrity, authentic, trusted)
v.levels;       // { integrity, authentic, trusted, time_anchored, finalized, onchain }
v.trust_basis;  // 'pinned-root' | 'override' | 'tls' | 'none'
v.reasons;      // [{ level, code, detail }]
```

```bash
npx fractalai-verify fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee            # exit 0
npx fractalai-verify ../deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json --anchors \
    --require integrity,authentic,trusted,time_anchored,finalized                                 # exit 0
```

Exit codes: 0 valid · 10 integrity · 11 authentic · 12 trusted · 13 time_anchored · 14 finalized · 15 onchain · 2 usage · 3 input.

Kinds: `midas-alert`, `x402-seal`, `acp-verdict`, `served-proof`, `self-attest-seal`, and (2.1)
`latam-stablecoin-receipt` — a receipt for an on-chain Transfer of a pinned LatAm stablecoin whose facts the kernel
recomputes from the chain with `checkOnchain: true` (level `onchain`, spec §12):

```js
const v = await verify(receiptText, { kind: 'latam-stablecoin-receipt', directory, checkOnchain: true,
  rpc: { 'eip155:137': [urlA, urlB] }, policy: { require: ['integrity', 'authentic', 'trusted', 'onchain'], rpcQuorum: 2 } });
v.onchain;      // recomputed { token, from, to, amount, block_number, block_hash, block_timestamp, confirmations, finalized, … }
```

- `trust-roots.json` — pinned governance key, directory checkpoint (epoch 3), anchor deployments
  (`chainId → contract + runtime code hash`), Solana genesis hashes and announced signers. Anything else you pass is
  an override and is reported. `latam-stablecoins.json` — the pinned stablecoin registry (§12.1).
- `verifySync()` — same decision, offline, never evaluates anchors or on-chain facts.
- Pass **raw JSON text**: the kernel parses it with its own strict parser (duplicate keys, lone surrogates, NaN and
  depth are refused). Object input is refused on engines that fail the load-time JSON self-test.

Not a CMVP/FIPS 140-3 module; no external audit. See the spec's §11 for the limits.
