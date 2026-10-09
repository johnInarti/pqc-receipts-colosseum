# FractalAI — post-quantum signed receipts and risk alerts for agent payments

Public companion repository for FractalAI's entry in Colosseum's **Crypto World's Fair** hackathon (Sept 14 – Oct 12, 2026).
It contains the parts of the system a third party needs to **verify our claims without trusting us**: the offline
verifiers, the golden conformance vectors, the anchor contracts, and the design docs. The node and the web app live in a
proprietary, closed-source codebase; everything here is either extracted from it verbatim or reproducible against
the live endpoints listed below.

> Honesty first. Everything we claim carries a live URL, a transaction hash or a command you can run.
> What we do **not** claim is listed at the end of this file. Read it before anything else.

## What is live today (verified 2026-10-02 from outside our infrastructure)

| Capability | Proof |
|---|---|
| Rust Layer-1 node, public JSON-RPC, chain id 62124, consensus signed with **ML-DSA-65 (FIPS 204, NIST level 3)** | `POST https://api.fractalai.net.co` → `eth_blockNumber` ≈ 1,067,718; `fractal_checkpointBundle` → `"algorithm":"ML-DSA-65 (FIPS-204)"`. **One validator, `net_peerCount` = 0.** |
| Chain registered upstream | https://github.com/ethereum-lists/chains/pull/8769 (merged) |
| **10 pay-per-call x402 endpoints** on Base (USDC, $0.005–$0.50) returning ML-DSA-65-signed receipts | https://fractalai.net.co/.well-known/x402.json (snapshot in `docs/x402-catalog-snapshot-2026-10-02.json`) |
| **Pay in Colombian pesos (COPM, Minteo) on Polygon** via x402 `exact` + Permit2, priced from the official TRM; the notary (`/api/x402/witness`) offers USDC/Base and COPM/Polygon side by side | `POST https://fractalai.net.co/api/x402/witness` → 402 lists `eip155:137` / COPM / `permit2`. Live since 2026-10-09; acceptance payments were internal (self-funded), not customer revenue |
| **Signed, epoch-chained, append-only key directory** (epoch 3; one rotation exercised in production) | https://fractalai.net.co/.well-known/x402-receipt-keys |
| Receipts reconstructible on-chain (`settle_block_number`, `settle_tx_index`, `settle_log_index`) | 7/7 routes verified on Base, GitHub Actions run 36284837150 |
| **MIDAS** signed liquidation-risk alerts (Aave V3, 6 chains, 10,315 tracked addresses, paper mode) | https://fractalai.net.co/api/midas/alerts/recent · browser verifier https://fractalai.net.co/midas/proof |
| **PQCReceiptAnchor** on Arbitrum One + Arc mainnet, real receipt anchored on each | see *Anchor contract* below |
| MidasRescueVault V2 (opt-in guardian, keeper in dry-run, 0 enrolments) | Base `0x654117c020BAD98Ce5c80C49BF318eF087E5D37C` |
| Verifier packages on npm | `@fractalai/x402-pqc-witness` 0.1.3 · `@fractalai/agent-passport-mcp` 0.2.5 · `@fractalai/pqc-agent-receipts-conformance` 0.3.1 |

Commercially the project is pre-revenue: **external paid demand to date ≈ US$0.16 from two unknown addresses, 0 paying
subscribers, treasury 99.01 USDC**. One founder (Colombia), no employees, no prior institutional funding.

## Trust Kernel v2 — one decision, one specification, one adversarial corpus

Every trust decision in this repository is made by **one** implementation, [`kernel/`](kernel/), specified normatively
in [`spec/TRUST-KERNEL.md`](spec/TRUST-KERNEL.md) and pinned down by an executable specification,
[`corpus/`](corpus/) (173 vectors: every proof of concept from four internal red-teams + real production positives +
the LatAm stablecoin receipts below).
`verifier/`, `conformance/` and the Python package delegate to it or reproduce it; both the JavaScript kernel and the
Python port pass the corpus at 100 %.

- **Pinned trust roots** (`kernel/trust-roots.json`): the directory's governance key and its epoch-3 checkpoint, the
  anchor contracts by chain id **and runtime code hash**, Solana genesis hashes. TLS is only a transport.
- **Only what is signed**: the signed message is rebuilt from a fixed domain; unsigned copies (facts, emitted_at,
  snapshot, ids) must match the signed bytes exactly; the receipt kind is chosen by the caller, never by the document.
- **Leveled verdict**: `{integrity, authentic, trusted, time_anchored, finalized}` + `trust_basis` + coded reasons;
  CLI exit code = first failed level.
- **Time from consensus**: block header time, `observedAt` bound to the signed time, finality, multi-RPC agreement;
  Solana: genesis, finalized + blockTime, local Ed25519, a single byte-exact memo. Test networks are marked.

## Verify a signed alert yourself (60 seconds, Node 20+)

```bash
cd kernel && npm install
node bin/fractalai-verify.mjs fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee        # VALID, exit 0
node bin/fractalai-verify.mjs ../deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json --anchors \
     --require integrity,authentic,trusted,time_anchored,finalized                                     # + Arc time proof
cd ../corpus && npm install && node run.mjs --live                                                   # 173/173 + live 4/4
```

The receipt is bound to the id you asked for, the signed message is rebuilt (never read from the receipt), the key
directory must verify against the **pinned** governance key and checkpoint, and the key must be authorized for that
receipt kind at the receipt's **signed** time. `verifier/verify-midas-alert.mjs` does the same through the
compatibility layer.

## LatAm Stablecoin Receipts (Trust Kernel 2.1, kind `latam-stablecoin-receipt`)

A post-quantum (ML-DSA-65) receipt that a transfer of a **pinned** Latin-American stablecoin — COPM (Polygon), BRLA
(Polygon, Base), MXNB (Arbitrum One, Base), wARS / wBRL (Base) — already happened on-chain: token, amount (smallest
units + decimal), from, to, tx, log index, block number / hash / time, confirmations and finality. The issuer reads the
`Transfer` log from public RPCs (never from the requester) and refuses reverted transactions, foreign or look-alike
contracts, mints/burns, non-canonical blocks and unfinalized blocks; the verifier (JS kernel and Python port)
recomputes every fact from the chain (level `onchain`, multi-RPC) on top of the signature and key checks. Spec §12;
use cases, limits and the proposed x402 endpoint in [`docs/LATAM-STABLECOIN-RECEIPTS.md`](docs/LATAM-STABLECOIN-RECEIPTS.md).

```bash
cd issuer && npm install && npm test                   # real COPM/BRLA/MXNB transfers replayed; refusals; CLI end to end
node bin/fractalai-stablecoin-receipt.mjs keygen --out /tmp/test-key.json          # EPHEMERAL test key
node bin/fractalai-stablecoin-receipt.mjs issue --chain 137 \
  --tx 0x735bed7c7404f259b71b3ce6b3a1e26e65f9edad1602653754e79a1a251b29f1 --key /tmp/test-key.json \
  --rpc https://polygon-bor-rpc.publicnode.com --rpc https://polygon.drpc.org --out /tmp/copm.json
node ../kernel/bin/fractalai-verify.mjs /tmp/copm.json --kind latam-stablecoin-receipt --trusted-key <public_key_b64> \
  --onchain --rpc eip155:137=https://polygon-bor-rpc.publicnode.com --require integrity,authentic,trusted,onchain
```

Not yet in production: no directory key with `use = stablecoin-receipt` is published, so production receipts of
this kind do not exist yet (test keys only; see the doc for what is missing).

## Repository layout

```
spec/          TRUST-KERNEL.md — normative specification (threat model, algorithm, domain table, limits)
kernel/        Trust Kernel v2 — the single reference implementation (+ CLI fractalai-verify, trust-roots.json,
               latam-stablecoins.json)
issuer/        latam-stablecoin-receipt issuer (library + CLI; operator-supplied ML-DSA-65 key; read-only RPC)
corpus/        adversarial + positive golden corpus (executable spec; JS and Python runners)
redteam/       the red-team PoCs replayed against the kernel (run-all.sh)
verifier/      offline verifiers (ML-DSA-65 seals, MIDAS alerts, EVM + Solana Memo anchor checks) + tests
conformance/   neutral conformance suite + golden vectors for PQC-signed agent receipts (7 profiles: x402 served,
               x402 SAR, ACP verdict, RFC 9964 JOSE, W3C VC-DI, wg-identity HAI, A2A signed-receipts/v1)
contracts/     PQCReceiptAnchor.sol (write-once, ownerless timestamp anchor; 20/20 Hardhat tests) and
               FractalCheckpoint.sol (append-only accountability anchor on Base)
python/       fractalai-pqc-verify: the same offline verifier + 7 conformance vectors for Python agents
docs/          MIDAS signed alerts, key rotation / directory design, rescue vault V2, FRC-55R asset layer,
               Arbitrum anchor design, x402 catalog snapshot
```

### Conformance suite

```bash
cd conformance && npm install && node src/check.mjs   # → CONFORMANT — 7/7 profiles (authentic · fail-closed · tamper✗ · forgery✗)
```

Fail-closed by design: a valid signature only proves *some* key signed the bytes. `valid` is true only when the signature
verifies **and** the key is in your trusted set (the anchored key directory). Every profile ships a genuine, a tampered and a
different-key forgery vector.

### Python (LangChain, CrewAI, any Python agent)

`python/` holds `fractalai-pqc-verify`, a 1:1 Python port of the verifier and the conformance suite (same JCS
canonicalization, same domain separation, same fail-closed rule). Not on PyPI yet; install from this repo:

```bash
pip install "git+https://github.com/johnInarti/pqc-receipts-colosseum.git#subdirectory=python"
fractalai-verify midas          # verifies public receipt fe62b072… end to end
fractalai-verify conformance    # → CONFORMANT — 7/7 profiles
```

```python
from fractalai_pqc_verify import fetch_key_directory, verify_receipt
result = verify_receipt(receipt, fetch_key_directory())   # valid only if signature OK AND key active
```

ML-DSA-65 backend: pure-Python `dilithium-py` by default, optional PQClean C backend via `pqcrypto`
(`[fast]`); tests cross-check both against the production signer. Not a CMVP-validated module. Tool examples for
LangChain and CrewAI are in `python/examples/` (neither framework is a dependency). Details: `python/README.md`.

### Anchor contract

`contracts/PQCReceiptAnchor.sol` records, exactly once per `receiptId = sha256(signature)`, the `payloadHash`, the key id and
the issuer-claimed `observedAt`. It proves existence-by-time and integrity; it does **not** verify ML-DSA-65 on-chain (that is
done offline). No owner, no funds, no upgrade. **Deployed on two mainnets on 2026-10-03, each with a real receipt anchored**
(MIDAS alert `fe62b072…`, `receiptId 0xb9b47ba8…94eb`):

| Chain | Contract | Deploy tx | Anchor tx |
|---|---|---|---|
| Arbitrum One (42161) | [`0x3A23c614033cb22139DC13932524767c5fE841d8`](https://arbiscan.io/address/0x3A23c614033cb22139DC13932524767c5fE841d8) | `0xb42b8df36438a195fc629e15926142dea386aa9fc6ca597c982c9fc0fb0aff44` | see `docs/ARBITRUM-PQC-RECEIPT-ANCHOR.md` |
| Arc mainnet (5042, Circle) | [`0x1f0d2774943250A7EB179e960203ea86319a8181`](https://explorer.arc.io/address/0x1f0d2774943250A7EB179e960203ea86319a8181) | `0xa5b2b9acc0379aab20882de7a90e416dd81106efb26b8e81ef90ba4560d18f47` | [`0x31979b7f…6b64`](https://explorer.arc.io/tx/0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64) (logIndex 5) |

ABIs and full records: `deployments/`. Source is not yet verified on Arbiscan (no API key); bytecode matches `solc 0.8.24`,
optimizer 200 runs, viaIR, cancun. Total cost of both deployments + anchors: under US$0.05.

| Solana mainnet (SPL Memo) | announced signer [`7cpTE4C7…mN624`](https://explorer.solana.com/address/7cpTE4C7sRWsHyeGsiqTfwNv9ntyribrRJV3s8vmN624) (no contract: Memo program) | — | [`cHiTTWYg…Ftw`](https://explorer.solana.com/tx/cHiTTWYgizzjyQAMdF4DyPdF7m6w21wJdgzCwb3G5r1Qy12wyFxi6zjPEHg271nj2tXNNFyMvGHR6S6gjgs6Ftw) (slot 454584215, finalized) |

**Solana mainnet: anchored and verified on 2026-10-08** — the same `fractalai.pqc-receipt-anchor/1` ids carried in an SPL
Memo signed by the announced Ed25519 key (fee 5000 lamports). Independently verified by the JS and Python Trust Kernel
implementations: VALID on all five levels (integrity, authentic, trusted, time_anchored, finalized), trust basis
`pinned-root`. Record: `deployments/anchors/solana-mainnet-beta-fe62b072.json`; tooling: `scripts/anchor-solana-memo.mjs`,
`verifier/verify-solana-anchor.mjs`, `docs/SOLANA-PQC-RECEIPT-ANCHOR.md`. Memo does not verify anything on-chain: ML-DSA-65
is verified off-chain; the anchor proves existence-by-time.

### Reproduce the Arc deployment

`scripts/cctp-bridge-base-to-arc.mjs` (CCTP v2 + Circle Forwarding Service, Base → Arc, 16 s end to end),
`scripts/deploy-pqc-receipt-anchor.js` and `scripts/anchor-public-receipt.js`. Keys are read from the environment only.
Full record with every tx: `docs/ARC-PQC-RECEIPT-ANCHOR.md` and `deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json`.

## Use it in CI (GitHub Action)

```yaml
- uses: johnInarti/pqc-receipt-verify-action@v2
  with:
    receipt: fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee
```
Fail-closed: the step fails if the ML-DSA-65 signature, the receipt id or the key trust does not check out.
Source and tests: https://github.com/johnInarti/pqc-receipt-verify-action

## Development history disclosure (Colosseum rule)

Colosseum judges only the work done between **Sept 14 and Oct 12, 2026** and requires disclosure of pre-existing code.
Pre-existing (before Sept 14): the Rust node, the ML-DSA-65 consensus signer, the first x402 routes, the first MIDAS scanner.
Built during the hackathon window (commits dated in our private codebase, hashes in `docs/`): reconstructible receipts
(block + logIndex) and the JCS canonicalization fix; the signed, epoch-chained key directory and two key rotations in
production (epochs 2 and 3); MIDAS signed alerts, `/midas/proof` and the public alert-receipt API; the discovery rewrite of the
radar (0 → 10,315 tracked addresses) and the missed-opportunity ledger; MidasRescueVault V2 + keeper; FRC-55R asset layer and
the Sentinel asset; `PQCReceiptAnchor.sol` and the anchor verifier; the conformance suite v0.3.

## What we do NOT claim

- Not decentralized, no Byzantine fault tolerance: one validator, zero peers.
- No external security audit of the node, consensus, asset layer or contracts (internal adversarial testing only).
- Not CNSA 2.0 (we are NIST level 3, not level 5), not FIPS 140-3 / CMVP validated, no "quantum-safe certification".
- ML-KEM/Kyber is implemented and tested in the crypto crate but **not used by the node**. No proprietary "fractal" or
  "quantum" layer strengthens the NIST algorithms; those prototypes were withdrawn.
- No revenue, users or TVL to speak of (≈ $0.16 external, 0 subscribers). MIDAS trades nothing (paper mode, 0 trades,
  directional model hit rate 46 %, `edge_detected:false`). Rescue V2 is opt-in, best-effort, 0 enrolments.
- A signed receipt proves that specific bytes were signed by a specific key at a specific time — not that its content is true.
- Trust Kernel v2 limits: without a light client the verifier believes the RPCs you configure (several must agree);
  the governance key and checkpoint were pinned from our TLS-served directory on 2026-10-07 (trust on first use, the
  on-chain directory anchor is still pending); Arbitrum/Arc/Solana block times carry their protocols' tolerances;
  `@noble` / `dilithium-py` are not CMVP-validated modules; the kernel has had internal red-teams only, no external
  audit. Details: `spec/TRUST-KERNEL.md` §11.

## License

Apache-2.0 for code in `verifier/`, `conformance/` and `python/`; MIT for `contracts/` (SPDX headers in each file).
Docs © 2026 FRACTAL AI S.A.S., shared for review.

Contact: softnextceo@gmail.com · https://fractalai.net.co
