/**
 * Runnable: an AP2 v0.2 purchase (artifacts produced by the official AP2 SDK) → FractalAI countersigns a
 * post-quantum fulfillment receipt → it travels inside the A2A Artifact the buyer receives → the buyer verifies.
 *   node examples/ap2-a2a-fulfillment.ts
 */
import { readFileSync } from 'node:fs';
import { issueAp2FulfillmentReceipt, verifyAp2Fulfillment } from '../src/ap2.ts';
import { attachReceipt, extractReceiptText, artifactPartsDigestInput } from '../src/a2a.ts';
import type { A2AArtifact } from '../src/a2a.ts';
import { testTrust } from '../src/testing.ts';

const fx = JSON.parse(readFileSync(new URL('../fixtures/ap2/flow-v0.2.json', import.meta.url), 'utf8'));
const T = testTrust(); // TEST issuer key; production needs a published commerce-receipt key
const flow = {
  paymentReceiptJwt: fx.payment_receipt_jwt, paymentReceiptIssuerJwk: fx.keys.mpp,
  checkoutReceiptJwt: fx.checkout_receipt_jwt, checkoutReceiptIssuerJwk: fx.keys.merchant,
  closedPaymentMandate: fx.closed_payment_mandate, closedCheckoutMandate: fx.closed_checkout_mandate,
};
const artifact: A2AArtifact = { artifactId: 'art-q3-report', name: 'Q3 market report', parts: [{ data: JSON.parse(fx.delivered.content), mediaType: 'application/json' }] };

// merchant side (or FractalAI as witness): verify AP2's ES256 receipts, then countersign with ML-DSA-65
const receipt = await issueAp2FulfillmentReceipt(flow, { bytes: artifactPartsDigestInput(artifact), mediaType: 'application/json' }, T.issuer.signer);
const delivered = attachReceipt(artifact, receipt);

// buyer side: what arrived over A2A
const decision = await verifyAp2Fulfillment(extractReceiptText(delivered)!, flow, { bytes: artifactPartsDigestInput(delivered) }, T.opts);
console.log(JSON.stringify({
  commerce_id: receipt.commerce_id,
  payment_id: receipt.commerce.payment.payment_id,
  kernel: { valid: decision.verdict.valid, levels: decision.verdict.levels, trust_basis: decision.verdict.trust_basis },
  profile: decision.profile,
  accepted: decision.accepted,
  receipt_bytes: JSON.stringify(receipt).length,
}, null, 2));
