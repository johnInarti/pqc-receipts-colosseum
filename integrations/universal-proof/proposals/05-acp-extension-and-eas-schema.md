# DRAFTS — not submitted. Lower priority (not implemented in code yet)

**Author:** John Edward Romo Sanchez (FractalAI, KPITAPP SAS). Drafted with AI assistance (Claude).

## A. ACP (agentic-commerce-protocol) — capability extension `co.net.fractalai.pqc-receipt`

Following `rfcs/rfc.extensions.md`:

```json
{ "name": "co.net.fractalai.pqc-receipt", "extends": ["$.Order.pqc_receipt"],
  "schema": "https://fractalai.net.co/acp/pqc-receipt/v1/schema.json", "spec": "https://fractalai.net.co/acp/pqc-receipt/v1" }
```

`Order.pqc_receipt` would be an `agent-commerce-receipt` with profile `acp.order/1`. It binds the checkout session
id, the order id, the hash of the canonical order JSON and the hash of the delivered digital good. The merchant
returns it in the complete response and in the order webhook.

Today ACP has `OrderConfirmation.receipt_url` and HMAC-signed webhooks, but no cryptographic receipt.

**Status:** design only. It needs ACP sandbox access to build fixtures against a real implementation; synthetic
fixtures would not be presented as real.

## B. EAS — schema for anchoring commerce receipts

```
bytes32 commerceId, bytes32 deliverySha256, string protocolProfile, string receiptURI
```

- `refUID` chains the attestation to a payment attestation or to the agent passport, when one exists.
- The EAS attestation itself is ECDSA; the post-quantum signature lives in the document at `receiptURI`, whose
  sha256 is `commerceId`.
- Registering a schema needs no permission. It needs a funded deployer address, which is a founder decision.
