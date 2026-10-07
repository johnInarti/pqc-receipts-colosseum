# @fractalai/pqc-trust-kernel — Trust Kernel v2

The single reference implementation of FractalAI's receipt-trust decision (spec: [`../spec/TRUST-KERNEL.md`](../spec/TRUST-KERNEL.md)).
Pure ESM, dependencies: `@noble/post-quantum`, `@noble/hashes`, `@noble/curves`. Node ≥ 20.

```js
import { verify } from '@fractalai/pqc-trust-kernel';
const v = await verify(receiptJsonText, { kind: 'midas-alert', directory: directoryJsonText });
v.valid;        // policy-required levels all true (default: integrity, authentic, trusted)
v.levels;       // { integrity, authentic, trusted, time_anchored, finalized }
v.trust_basis;  // 'pinned-root' | 'override' | 'tls' | 'none'
v.reasons;      // [{ level, code, detail }]
```

```bash
npx fractalai-verify fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee            # exit 0
npx fractalai-verify ../deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json --anchors \
    --require integrity,authentic,trusted,time_anchored,finalized                                 # exit 0
```

Exit codes: 0 valid · 10 integrity · 11 authentic · 12 trusted · 13 time_anchored · 14 finalized · 2 usage · 3 input.

- `trust-roots.json` — pinned governance key, directory checkpoint (epoch 3), anchor deployments
  (`chainId → contract + runtime code hash`), Solana genesis hashes and announced signers. Anything else you pass is
  an override and is reported.
- `verifySync()` — same decision, offline, never evaluates anchors.
- Pass **raw JSON text**: the kernel parses it with its own strict parser (duplicate keys, lone surrogates, NaN and
  depth are refused). Object input is refused on engines that fail the load-time JSON self-test.

Not a CMVP/FIPS 140-3 module; no external audit. See the spec's §11 for the limits.
