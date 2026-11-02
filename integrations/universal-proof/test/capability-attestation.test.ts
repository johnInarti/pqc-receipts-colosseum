/**
 * Optional capability attestation reference in an A2A delivery receipt (a2aproject/A2A discussion #2330).
 * The attestation document below is a stand-in: its format and signature belong to whoever issues it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { issueReceipt, verifyReceipt, signedBody } from '../src/core.ts';
import { buildAp2FulfillmentBody, verifyAp2Fulfillment } from '../src/ap2.ts';
import type { Ap2Flow } from '../src/ap2.ts';
import { attachReceipt, attachCapabilityAttestation, extractCapabilityAttestation, extractReceiptText, artifactPartsDigestInput } from '../src/a2a.ts';
import type { A2AArtifact } from '../src/a2a.ts';
import { capabilityAttestationRef, capabilityAttestationBinding, checkCapabilityAttestation, checkCapabilityAttestationRef, CAPABILITY_ATTESTATION_BINDING } from '../src/attestation.ts';
import { testTrust } from '../src/testing.ts';

const fx = JSON.parse(readFileSync(new URL('../fixtures/ap2/flow-v0.2.json', import.meta.url), 'utf8'));
const T = testTrust();
const flow: Ap2Flow = {
  paymentReceiptJwt: fx.payment_receipt_jwt, paymentReceiptIssuerJwk: fx.keys.mpp,
  checkoutReceiptJwt: fx.checkout_receipt_jwt, checkoutReceiptIssuerJwk: fx.keys.merchant,
  closedPaymentMandate: fx.closed_payment_mandate, closedCheckoutMandate: fx.closed_checkout_mandate,
};
const artifact: A2AArtifact = { artifactId: 'art-q3-report', parts: [{ data: JSON.parse(fx.delivered.content), mediaType: 'application/json' }] };
const delivered = { bytes: artifactPartsDigestInput(artifact), mediaType: 'application/json' };

const doc = JSON.stringify({ subject: 'agent-card-sha256:00', verdicts: { pass: 11, fail: 0, inconclusive: 1, untested: 2 } });
const ref = capabilityAttestationRef(doc, {
  issuer: 'https://attestor.example', key_id: 'att-key-1', uri: 'https://attestor.example/a/123.json',
  algorithm: 'es256', issued_at: 1_700_000_000, expires_at: 1_900_000_000,
});

async function issueWith(r = ref) {
  const body = buildAp2FulfillmentBody(flow, delivered, 1_793_000_000);
  body.bindings = { ...body.bindings, ...capabilityAttestationBinding(r) };
  return issueReceipt(body, T.issuer.signer);
}

test('issue with attestation → carry in A2A → kernel + AP2 profile + attestation check: all accepted', async () => {
  const receipt = await issueWith();
  const carried = attachCapabilityAttestation(attachReceipt(artifact, receipt), ref);
  const d = await verifyAp2Fulfillment(extractReceiptText(carried)!, flow, { bytes: artifactPartsDigestInput(carried) }, T.opts);
  assert.equal(d.accepted, true, JSON.stringify(d.verdict.reasons));
  const p = checkCapabilityAttestation(signedBody(d.verdict)!, extractCapabilityAttestation(carried), { document: doc, now: 1_850_000_000 });
  assert.equal(p.ok, true, JSON.stringify(p));
  assert.deepEqual(p.checked, [CAPABILITY_ATTESTATION_BINDING, 'capability_attestation_valid_at_issuance', 'capability_attestation_not_expired', 'capability_attestation_document']);
  // carrying the reference does not change the delivery hash (metadata is excluded)
  assert.equal(artifactPartsDigestInput(carried), delivered.bytes);
});

test('a swapped reference (another genuine-looking attestation) is refused', async () => {
  const body = signedBody(await verifyReceipt(await issueWith(), T.opts))!;
  const other = capabilityAttestationRef('{"other":true}', { ...ref, issued_at: ref.issued_at, expires_at: ref.expires_at });
  const p = checkCapabilityAttestation(body, other);
  assert.equal(p.ok, false);
  assert.match(p.failures.join(';'), /differs from the one the receipt signed/);
});

test('document bytes that do not match the digest are refused; expired and not-yet-valid attestations too', async () => {
  const body = signedBody(await verifyReceipt(await issueWith(), T.opts))!;
  assert.match(checkCapabilityAttestation(body, ref, { document: doc + ' ' }).failures.join(';'), /do not match the referenced digest/);
  assert.match(checkCapabilityAttestation(body, ref, { now: 1_900_000_000 }).failures.join(';'), /has expired/);
  const late = capabilityAttestationRef(doc, { ...ref, issued_at: 1_793_100_000, expires_at: 1_950_000_000 });
  const lateBody = signedBody(await verifyReceipt(await issueWith(late), T.opts))!;
  assert.match(checkCapabilityAttestation(lateBody, late).failures.join(';'), /not valid when the receipt was issued/);
});

test('absent on both sides: nothing claimed, check passes; presented without commitment: refused', async () => {
  const plain = signedBody(await verifyReceipt(await issueReceipt(buildAp2FulfillmentBody(flow, delivered), T.issuer.signer), T.opts))!;
  assert.equal(checkCapabilityAttestation(plain, undefined).ok, true);
  assert.match(checkCapabilityAttestation(plain, ref).failures.join(';'), /does not commit to any/);
  const committed = signedBody(await verifyReceipt(await issueWith(), T.opts))!;
  assert.equal(checkCapabilityAttestation(committed, undefined).ok, false, 'committed but not presented');
});

test('reference shape is strict: unknown keys, non-https uri, bad digest, inverted times', () => {
  assert.throws(() => checkCapabilityAttestationRef({ ...ref, score: 99 }), /exactly the keys/);
  assert.throws(() => checkCapabilityAttestationRef({ ...ref, uri: 'http://attestor.example/a.json' }), /https/);
  assert.throws(() => checkCapabilityAttestationRef({ ...ref, digest: { alg: 'sha-256', value: 'ABC' } }), /64 lowercase hex/);
  assert.throws(() => checkCapabilityAttestationRef({ ...ref, expires_at: ref.issued_at }), /later than issued_at/);
  assert.equal(checkCapabilityAttestationRef(JSON.parse(JSON.stringify(ref))).digest.value, ref.digest.value, 'control: a valid reference passes');
});
