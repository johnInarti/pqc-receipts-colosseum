# DRAFT — not submitted. Target: FIDO Alliance (AP2 specification owner since 2026-04-28); AP2 repo accepts samples/SDK only

**Title:** Fulfillment countersignature for AP2 v0.2 receipts (delivered-content binding, post-quantum signature)

**Author:** John Edward Romo Sanchez (FractalAI, KPITAPP SAS). Drafted with AI assistance (Claude).

## Context (what AP2 v0.2 already has)

AP2 v0.2 returns an ES256-signed Checkout Receipt and Payment Receipt. Each one binds a closed mandate through
`reference` = base64url(sha256(closed mandate SD-JWT)). Together with the mandates, they form the "Dispute Evidence"
that the specification describes. This proposal does not replace or modify any of that.

## Gap

The receipts bind *payment* and *checkout* state. They do not bind *what was delivered*, so for digital goods and
agent services the dispute evidence stops at "paid". They are also signed with P-256 only.

## Proposal

An optional fulfillment countersignature, profile `ap2.fulfillment/1`. It is signed with ML-DSA-65 (FIPS 204) and
covers:

- `sha256` of each receipt JWT and its `iss` and `reference`;
- `payment_id`, `psp_confirmation_id`, `network_confirmation_id` and `order_id`;
- `sha256` of the delivered content.

The countersigner (the merchant, or a third-party witness) MUST verify both ES256 receipts, and the closed mandates
when it holds them, before signing. A relying party re-derives every binding from the AP2 artifacts it holds.

Over A2A it travels in `Artifact.metadata` under an extension URI. It could also be registered as an AP2 extension
point if FIDO prefers.

## Evidence

Fixtures were produced with the official AP2 Python SDK (commit `e1ea56db`): open and closed mandates, SD-JWT and
KB-SD-JWT chains, ES256 receipts self-verified with `ReceiptClient.verify_receipt`. Countersignature and verification
are in `src/ap2.ts`, with 9/9 tests. The tests cover:

- the Error receipt and the wrong issuer key, which are refused at issuance;
- a mismatch between mandate and receipt;
- a substituted receipt;
- a compromised countersigner forging `payment_id`, which is caught by the profile;
- key-use separation.

## Limits

- This adds a signature; it does not make AP2 post-quantum. The mandates and receipts remain ES256.
- The countersignature proves the binding at time T, not the quality of the delivery.
- No production key is published yet.
