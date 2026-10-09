import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeBody, issueReceipt, verifyReceipt, verifyReceiptSync, receiptBytes, COMMERCE_DOMAIN, sha256Of } from '../src/core.ts';
import { testTrust } from '../src/testing.ts';
import { SPEC_VERSION } from '@fractalai/pqc-trust-kernel';

const T = testTrust();
const body = () => makeBody({ protocol: 'spei', profile: 'spei.cep/1', payment: { clave_rastreo: 'MBAN01002610090000123456' }, bindings: { cep_xml_sha256: sha256Of('<cep/>') }, delivery: { sha256: sha256Of('service') } });

test('kernel is spec 2.2 (agent-commerce-receipt available)', () => assert.equal(SPEC_VERSION, '2.2.0'));

test('issue → verify (async and offline) with a test directory', async () => {
  const r = await issueReceipt(body(), T.issuer.signer);
  assert.ok(r.signed_message.startsWith(`${COMMERCE_DOMAIN}\n`));
  const v = await verifyReceipt(new TextDecoder().decode(receiptBytes(r)), T.opts);
  assert.equal(v.valid, true, JSON.stringify(v.reasons));
  assert.equal(v.kind, 'agent-commerce-receipt');
  assert.equal(verifyReceiptSync(r, T.opts).valid, true);
});

test('makeBody enforces the closed shape (non-ASCII, numbers, >16 entries)', () => {
  assert.throws(() => makeBody({ protocol: 'pix', profile: 'pix.e2e/1', payment: { pagador: 'João' }, bindings: {}, delivery: { sha256: sha256Of('x') } }), /COMMERCE_MALFORMED/);
  assert.throws(() => makeBody({ protocol: 'pix', profile: 'pix.e2e/1', payment: { amount: 5 as unknown as string }, bindings: {}, delivery: { sha256: sha256Of('x') } }), /COMMERCE_MALFORMED/);
  const many = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, 'v']));
  assert.throws(() => makeBody({ protocol: 'pix', profile: 'pix.e2e/1', payment: many, bindings: {}, delivery: { sha256: sha256Of('x') } }), /COMMERCE_MALFORMED/);
});

test('the document never chooses its kind: a commerce receipt cannot be verified as another kind', async () => {
  const r = await issueReceipt(body(), T.issuer.signer);
  const { verify } = await import('@fractalai/pqc-trust-kernel');
  const v = await verify(JSON.stringify(r), { ...T.opts, kind: 'x402-seal' });
  assert.equal(v.valid, false);
  assert.equal(v.levels.integrity, false);
});
