/**
 * AP2 v0.2 fulfillment receipts against REAL artifacts produced by the official AP2 Python SDK
 * (fixtures/ap2/flow-v0.2.json, scripts/gen_ap2_fixtures.py), carried over A2A v1 Artifact metadata.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { issueReceipt, verifyReceipt, signedBody } from '../src/core.ts';
import { ap2Reference, buildAp2FulfillmentBody, issueAp2FulfillmentReceipt, verifyAp2Fulfillment, checkAp2Fulfillment, verifyEs256 } from '../src/ap2.ts';
import type { Ap2Flow } from '../src/ap2.ts';
import { attachReceipt, extractReceiptText, artifactPartsDigestInput, agentCardExtension, FRACTALAI_A2A_EXTENSION } from '../src/a2a.ts';
import type { A2AArtifact } from '../src/a2a.ts';
import { testTrust } from '../src/testing.ts';

const fx = JSON.parse(readFileSync(new URL('../fixtures/ap2/flow-v0.2.json', import.meta.url), 'utf8'));
const T = testTrust();
const flow: Ap2Flow = {
  paymentReceiptJwt: fx.payment_receipt_jwt, paymentReceiptIssuerJwk: fx.keys.mpp,
  checkoutReceiptJwt: fx.checkout_receipt_jwt, checkoutReceiptIssuerJwk: fx.keys.merchant,
  closedPaymentMandate: fx.closed_payment_mandate, closedCheckoutMandate: fx.closed_checkout_mandate,
};
const artifact: A2AArtifact = { artifactId: 'art-q3-report', name: 'Q3 market report', parts: [{ data: JSON.parse(fx.delivered.content), mediaType: 'application/json' }] };
const delivered = { bytes: artifactPartsDigestInput(artifact), mediaType: 'application/json' };

test('fixture sanity: the official-SDK receipts verify with ES256 and bind the closed mandates', () => {
  assert.equal(verifyEs256(fx.payment_receipt_jwt, fx.keys.mpp).reference, ap2Reference(fx.closed_payment_mandate));
  assert.equal(verifyEs256(fx.checkout_receipt_jwt, fx.keys.merchant).reference, ap2Reference(fx.closed_checkout_mandate));
  assert.deepEqual(fx.sdk_self_check, { payment_receipt: { verified: true }, checkout_receipt: { verified: true } });
});

test('issue → attach to A2A artifact → extract → kernel + profile: accepted', async () => {
  const receipt = await issueAp2FulfillmentReceipt(flow, delivered, T.issuer.signer);
  assert.equal(receipt.commerce.payment.payment_id, verifyEs256(fx.payment_receipt_jwt, fx.keys.mpp).payment_id);
  const carried = attachReceipt(artifact, receipt);
  assert.deepEqual(carried.extensions, [FRACTALAI_A2A_EXTENSION]);
  const text = extractReceiptText(carried);
  assert.ok(text);
  // the client recomputes the delivery hash from the parts it received (metadata excluded)
  const d = await verifyAp2Fulfillment(text!, flow, { bytes: artifactPartsDigestInput(carried) }, T.opts);
  assert.equal(d.verdict.valid, true, JSON.stringify(d.verdict.reasons));
  assert.equal(d.verdict.trust_basis, 'override');
  assert.equal(d.accepted, true, JSON.stringify(d.profile));
  assert.ok(d.profile!.checked.includes('payment_receipt_sha256') && d.profile!.checked.includes('checkout_mandate_ref'));
});

test('A2A: tampered artifact parts are detected (delivery.sha256)', async () => {
  const receipt = await issueAp2FulfillmentReceipt(flow, delivered, T.issuer.signer);
  const carried = attachReceipt(artifact, receipt);
  const tampered: A2AArtifact = { ...carried, parts: [{ data: { ...JSON.parse(fx.delivered.content), pages: 4 }, mediaType: 'application/json' }] };
  const d = await verifyAp2Fulfillment(extractReceiptText(tampered)!, flow, { bytes: artifactPartsDigestInput(tampered) }, T.opts);
  assert.equal(d.verdict.valid, true);
  assert.equal(d.accepted, false);
  assert.match(d.profile!.failures.join(';'), /delivered content does not match/);
});

test('A2A: receipt metadata without the extension URI declared is not picked up', () => {
  const carried = attachReceipt(artifact, { x: 1 } as never);
  assert.equal(extractReceiptText({ ...carried, extensions: [] }), null);
  assert.equal(agentCardExtension().uri, FRACTALAI_A2A_EXTENSION);
});

test('issuer refuses: AP2 Error receipt, wrong issuer key, mandate/receipt mismatch', () => {
  assert.throws(() => buildAp2FulfillmentBody({ ...flow, paymentReceiptJwt: fx.payment_receipt_error_jwt }, delivered), /status is Error/);
  assert.throws(() => buildAp2FulfillmentBody({ ...flow, paymentReceiptIssuerJwk: fx.keys.merchant }, delivered), /ES256 signature does not verify/);
  assert.throws(() => buildAp2FulfillmentBody({ ...flow, closedPaymentMandate: fx.closed_checkout_mandate }, delivered), /reference != hash of the closed payment mandate/);
});

test('relying party: a receipt presented with ANOTHER genuine AP2 payment receipt fails the profile', async () => {
  const receipt = await issueAp2FulfillmentReceipt(flow, delivered, T.issuer.signer);
  const v = await verifyReceipt(receipt, T.opts);
  const p = checkAp2Fulfillment(signedBody(v)!, { ...flow, paymentReceiptJwt: fx.payment_receipt_error_jwt }, delivered);
  assert.equal(p.ok, false);
  assert.match(p.failures.join(';'), /AP2 artifacts do not verify/);
});

test('compromised issuer: validly signed body with a forged payment_id is refused by the profile', async () => {
  const body = buildAp2FulfillmentBody(flow, delivered);
  body.payment.payment_id = 'pay_forged';
  const forged = await issueReceipt(body, T.issuer.signer);
  const d = await verifyAp2Fulfillment(forged, flow, delivered, T.opts);
  assert.equal(d.verdict.valid, true);
  assert.equal(d.accepted, false);
  assert.match(d.profile!.failures.join(';'), /signed payment_id differs/);
});

test('key use: an x402-receipt key cannot issue AP2 fulfillment receipts (domain/use separation)', async () => {
  const r = await issueAp2FulfillmentReceipt(flow, delivered, T.x402Only.signer);
  const d = await verifyAp2Fulfillment(r, flow, delivered, T.opts);
  assert.equal(d.accepted, false);
  assert.equal(d.verdict.levels.trusted, false);
  assert.ok(d.verdict.reasons.some((x) => x.code === 'KEY_USE_MISMATCH'));
});

test('honesty: with the baked PRODUCTION roots the test issuer is not trusted (no commerce-receipt key published)', async () => {
  const r = await issueAp2FulfillmentReceipt(flow, delivered, T.issuer.signer);
  // the REAL production key directory (epoch 3, pinned by the kernel's baked roots)
  const prodDir = readFileSync(new URL('../.kernel/corpus/fixtures/directory-epoch3.json', import.meta.url), 'utf8');
  const v = await verifyReceipt(r, { directory: prodDir });
  assert.equal(v.valid, false);
  assert.equal(v.levels.authentic, true);
  assert.equal(v.trust_basis, 'pinned-root');
  assert.ok(v.reasons.some((x) => x.code === 'KEY_NOT_LISTED'), JSON.stringify(v.reasons));
  // and a test directory is refused by the pinned roots (its governance key is not FractalAI's)
  const v2 = await verifyReceipt(r, { directory: JSON.stringify(T.directory) });
  assert.ok(v2.reasons.some((x) => x.code.startsWith('DIRECTORY_')), JSON.stringify(v2.reasons));
});
