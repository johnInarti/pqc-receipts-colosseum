# FractalAI — post-quantum signed receipts and risk alerts for agent payments

Public companion repository for FractalAI's entry in Colosseum's **Crypto World's Fair** hackathon (Sept 14 – Oct 12, 2026).
It contains the parts of the system a third party needs to **verify our claims without trusting us**: the offline
verifiers, the golden conformance vectors, the anchor contracts, and the design docs. The node and the web app live in a
private monorepo (`johnInarti/FRACTAL-AI`); everything here is either extracted from it verbatim or reproducible against
the live endpoints listed below.

> Honesty first. Everything we claim carries a live URL, a transaction hash or a command you can run.
> What we do **not** claim is listed at the end of this file. Read it before anything else.

## What is live today (verified 2026-10-02 from outside our infrastructure)

| Capability | Proof |
|---|---|
| Rust Layer-1 node, public JSON-RPC, chain id 62124, consensus signed with **ML-DSA-65 (FIPS 204, NIST level 3)** | `POST https://api.fractalai.net.co` → `eth_blockNumber` ≈ 1,067,718; `fractal_checkpointBundle` → `"algorithm":"ML-DSA-65 (FIPS-204)"`. **One validator, `net_peerCount` = 0.** |
| Chain registered upstream | https://github.com/ethereum-lists/chains/pull/8769 (merged) |
| **10 pay-per-call x402 endpoints** on Base (USDC, $0.005–$0.50) returning ML-DSA-65-signed receipts | https://fractalai.net.co/.well-known/x402.json (snapshot in `docs/x402-catalog-snapshot-2026-10-02.json`) |
| **Signed, epoch-chained, append-only key directory** (epoch 3; one rotation exercised in production) | https://fractalai.net.co/.well-known/x402-receipt-keys |
| Receipts reconstructible on-chain (`settle_block_number`, `settle_tx_index`, `settle_log_index`) | 7/7 routes verified on Base, GitHub Actions run 36284837150 |
| **MIDAS** signed liquidation-risk alerts (Aave V3, 6 chains, 10,315 tracked addresses, paper mode) | https://fractalai.net.co/api/midas/alerts/recent · browser verifier https://fractalai.net.co/midas/proof |
| **PQCReceiptAnchor** on Arbitrum One + Arc mainnet, real receipt anchored on each | see *Anchor contract* below |
| MidasRescueVault V2 (opt-in guardian, keeper in dry-run, 0 enrolments) | Base `0x654117c020BAD98Ce5c80C49BF318eF087E5D37C` |
| Verifier packages on npm | `@fractalai/x402-pqc-witness` 0.1.3 · `@fractalai/agent-passport-mcp` 0.2.5 · `@fractalai/pqc-agent-receipts-conformance` 0.3.1 |

Commercially the project is pre-revenue: **external paid demand to date ≈ US$0.16 from two unknown addresses, 0 paying
subscribers, treasury 99.01 USDC**. One founder (Colombia), no employees, no prior institutional funding.

## Verify a signed alert yourself (60 seconds, Node 18+)

```bash
cd verifier && npm install
node verify-midas-alert.mjs            # verifies public receipt fe62b072… end to end
```

It checks: `receipt_id == sha256(canonical)`, the domain-separated message
`FRACTALAI-x402-served-v1\nmidas-alert\n<id>`, the ML-DSA-65 signature (`@noble/post-quantum`), and that the signing key is
`active` in the epoch-chained directory. Pin the directory after the first run if you do not want to trust our TLS.

## Repository layout

```
verifier/      offline verifiers (ML-DSA-65 seal verification, MIDAS alert check, Arbitrum anchor check) + tests
conformance/   neutral conformance suite + golden vectors for PQC-signed agent receipts (7 profiles: x402 served,
               x402 SAR, ACP verdict, RFC 9964 JOSE, W3C VC-DI, wg-identity HAI, A2A signed-receipts/v1)
contracts/     PQCReceiptAnchor.sol (write-once, ownerless timestamp anchor; 20/20 Hardhat tests) and
               FractalCheckpoint.sol (append-only accountability anchor on Base)
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

## Development history disclosure (Colosseum rule)

Colosseum judges only the work done between **Sept 14 and Oct 12, 2026** and requires disclosure of pre-existing code.
Pre-existing (before Sept 14): the Rust node, the ML-DSA-65 consensus signer, the first x402 routes, the first MIDAS scanner.
Built during the hackathon window (all commits dated in the private monorepo, hashes in `docs/`): reconstructible receipts
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

## License

Apache-2.0 for code in `verifier/` and `conformance/`; MIT for `contracts/` (SPDX headers in each file).
Docs © 2026 FRACTAL AI S.A.S., shared for review.

Contact: softnextceo@gmail.com · https://fractalai.net.co
