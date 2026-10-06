# PQC Agent-Receipt Conformance Suite (ML-DSA-65 / FIPS-204)

A **neutral, offline-verifiable conformance suite + golden vectors** for **post-quantum signed
receipts in agent commerce**. One artifact, seven profiles, verified with the audited
`@noble/post-quantum` `ml_dsa65` — no network, no trusted server, no rail changes.

```
node src/check.mjs        # → ✅ CONFORMANT — 7/7 profiles (authentic · fail-closed · tamper✗ · forgery✗)
```

**FAIL-CLOSED on key provenance.** A valid signature only proves SOME key signed the bytes — not that
FractalAI did. `verifyProfile(profile, entry, { trustedKeys })` returns `{ valid, signatureValid,
keyTrusted }` and `valid` is true only when the signature verifies AND the key is in your trusted set
(e.g. the anchored `/.well-known/x402-receipt-keys`). With no trusted key the result is
`valid:false` (authorship UNVERIFIED) — a self-signed forgery never earns a green check. Each profile
ships a genuine, a tampered, and a **different-key forgery** vector so the checker proves all of it.
Signing is deterministic (reproducible golden vectors).

## Why this exists

Six active standards are independently inventing *signed agent receipts / agent identity* right now
— and none of them ships a post-quantum path or golden interop vectors:

| Standard | Where | Open question this suite answers |
|---|---|---|
| **A2A** signed receipts | `a2aproject/A2A` #2150/#2152 (CSOAI `signed-receipts/v1`) | an ML-DSA-65 `alg` option alongside their Ed25519 reference — implemented below |
| **x402** Settlement Attestation Receipt | `coinbase/x402` #46 | a `signatureSchemes` entry beyond EIP-712/JWS |
| **AP2** dispute-evidence / proof-carrying receipt | `google-agentic-commerce/AP2` #338/#327 | a self-contained, verifiable receipt format |
| **W3C** `vc-di-quantum-resistant` | `w3c/vc-di-quantum-resistant` | a FIPS-204 cryptosuite + reference impl |
| **IETF COSE Receipts** (RFC 9942) + SCITT | `datatracker.ietf.org` | a *post-quantum* COSE Receipt profile |
| **x402 Foundation wg-identity** Hardware-Attested Agent Identity | `x402-foundation/wg-identity` #27 (Corrente Labs) | a software-only PQC path alongside the TEE hardware-quote path |

They all rest on the same substrate — **RFC 9964** ("Use of ML-DSA in JOSE and COSE", COSE code
point **−49**). So the same conformance suite, anchored to that published RFC, can answer the open
question in all six places at once. Whoever publishes the vectors everyone runs to claim
"PQC-receipt conformant" becomes the **referee across the agent-receipt space** — not a vendor inside
one protocol.

## Profiles (all ML-DSA-65 / FIPS-204)

- **`x402-served`** — FractalAI x402 served pay-per-proof: `DOMAIN\n<route>\n<digest>`, route-separated.
- **`sar`** — x402 Settlement Attestation Receipt (#46): `x402-sar-pqc-v1\n<sha256(JCS(core))>`.
- **`acp-verdict`** — Virtuals ACP Proof-Carrying Verdict: served proof over `sha256(JCS(decision))`.
- **`jose-ml-dsa-65`** — **RFC 9964 JOSE** (JWS compact) with `alg: "ML-DSA-65"`.
- **`vc-di-ml-dsa-65`** — **W3C VC Data Integrity**, cryptosuite `mldsa65-jcs-2024` (JCS; `hashData =
  sha256(JCS(proofConfig)) ‖ sha256(JCS(doc))`; `proofValue` = multibase base64url). Independent JS
  cross-validation for `w3c/vc-di-quantum-resistant`#31, in the spirit of its #35 (Rust cross-val) / #39
  (deterministic vectors). Byte-order/encoding align to the spec's exact `mldsa65-jcs-2024` text.
- **`hai-ml-dsa-65`** — Corrente Labs' Hardware-Attested Agent Identity strawman
  (`x402-foundation/wg-identity`#27 §3.1): `identity = {format, hardwareQuote, publicKey, timestamp,
  nonce}`. This profile is the additive, software-only PQC path — `identity.format:
  "eat+cwt+ml-dsa-65"` and `identity.pqc` carry an ML-DSA-65 signature over
  `sha256(JCS({publicKey, timestamp, nonce}))`, domain-separated as `FRACTALAI-hai-pqc-v1\n<digest>`
  — so agents without a TEE (no `hardwareQuote`) still get a verifiable identity binding, on the same
  schema as the hardware-attested path.
- **`a2a-receipt-ml-dsa-65`** — CSOAI's `signed-receipts/v1` A2A extension proposal
  (`a2aproject/A2A`#2150, spec+reference: `CSOAI-ORG/a2a-signed-receipts`): the receipt object
  (`schema`, `issuer`, `subject_card`, `task_id`, `claims`, `register`, `issued_at`, `content_id`) is
  unchanged; `signature.alg: "ML-DSA-65"` is an additive option alongside their Ed25519 reference,
  with `signer_public_key`/`sig` base64 (their example uses hex — an encoding choice, not a
  normative field). `content_id` and the signature both cover the exact same canonical-JSON bytes
  their reference implementation signs, so a verifier that already speaks the Ed25519 wire format
  only needs to branch on `alg` to accept this option.

Each vector in `vectors/` carries a **valid** receipt (must verify) and a **deliberately-invalid**
one (must be rejected) — a suite that only ever says "valid" measures nothing.

## Honest scope (read before citing it)

- Attests **authorship + integrity** of the receipt bytes (non-repudiation) — **not** that the
  underlying action/content is "correct".
- Uses the **FIPS-204 standardized algorithm** via an audited library; it is **not** a CMVP-validated
  cryptographic module. We don't imply certification we don't have.
- Trust in a signer's key is only as strong as its key directory; anchoring that directory (e.g. on
  Base) is a separate, disclosed step.
- We are **not** claiming "first PQC signed receipts" — `draft-rotzin-spice-afir-profile` already uses
  ML-DSA-65 for inference receipts. The differentiator here is **cross-standard, neutral conformance**:
  one measuring stick that the five surfaces above can all point to.
- Status: **pre-pilot**, with one real on-chain settlement (0.02 USDC on Base). Additive, never
  replacing the payment rail or the classical signature.

## A neutral governance home

Best homes for this to live as a neutral standard rather than a vendor repo: the **x402 Foundation
(Linux Foundation)** for the served-receipt/SAR side, **PQCA (Linux Foundation)** for neutrality, and
**IETF SCITT/COSE** for an "ML-DSA-65 profile for COSE Receipts" with running code. Contributions are
drafted for human review and posting — nothing here is auto-submitted anywhere.
