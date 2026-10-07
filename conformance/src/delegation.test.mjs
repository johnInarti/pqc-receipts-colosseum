/**
 * conformance ↔ Trust Kernel v2: the chain/directory/watchtower helpers delegate trust to the kernel.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { buildDirectory, verifyDirectory, kidForKey } from './key-directory.mjs';
import { verifyReceiptChain } from './verify-chain.mjs';
import { auditHistory } from './watchtower.mjs';
import { verifyProfile } from './profiles.mjs';

const b64 = (u) => Buffer.from(u).toString('base64');
const key = (b) => ml_dsa65.keygen(new Uint8Array(32).fill(b));
const GOV = '22'.repeat(32);
const govPk = b64(ml_dsa65.keygen(Uint8Array.from(Buffer.from(GOV, 'hex'))).publicKey);
const A = key(1), R = key(2);
const entry = (kp, extra) => { const pk = b64(kp.publicKey); return { kid: kidForKey(pk), use: 'x402-receipt', public_key_b64: pk, ...extra }; };
const dir = buildDirectory([entry(A, { status: 'active', not_before: 0, not_after: null }), entry(R, { status: 'revoked', not_before: 0, not_after: null })], GOV, { epoch: 1 });
const served = (kp) => { const sm = `FRACTALAI-x402-served-v1\nverify-agent\n${'ab'.repeat(32)}`; return { domain: 'FRACTALAI-x402-served-v1', route_id: 'verify-agent', digest: 'ab'.repeat(32), signed_message: sm, signature: b64(ml_dsa65.sign(new TextEncoder().encode(sm), kp.secretKey)), public_key: b64(kp.publicKey) }; };

test('verifyDirectory: pinned governance key → valid; unpinned self-signed directory is not trust', () => {
  const v = verifyDirectory(dir, { governanceKey: govPk });
  assert.equal(v.valid, true, v.reason);
  assert.deepEqual(v.trustedKeys, [b64(A.publicKey)], 'revoked keys are never "usable now"');
  const u = verifyDirectory(dir);
  assert.equal(u.valid, false);
  assert.equal(u.signatureValid, true);
});

test('verifyReceiptChain: x402-served goes through the kernel (active ok, revoked refused)', () => {
  assert.equal(verifyReceiptChain({ receipt: served(A), profile: 'x402-served', directory: dir, governanceKey: govPk }).trusted, true);
  const r = verifyReceiptChain({ receipt: served(R), profile: 'x402-served', directory: dir, governanceKey: govPk });
  assert.equal(r.trusted, false);
  assert.match(r.reason, /KEY_REVOKED/);
});

test('watchtower: consistent history passes; equivocation flagged', () => {
  const ok = auditHistory([{ at: 1, directory: dir }], { governanceKey: govPk });
  assert.equal(ok.ok, true, JSON.stringify(ok.alerts));
  const fork = buildDirectory([entry(A, { status: 'active', not_before: 0, not_after: null })], GOV, { epoch: 1 });
  const bad = auditHistory([{ at: 1, directory: dir }, { at: 2, directory: fork }], { governanceKey: govPk });
  assert.ok(bad.alerts.some((a) => a.code === 'equivocation'));
});

test('profiles: entry.profile cannot re-route; String() coercion and lax encodings refused (N2/F3)', () => {
  const v = JSON.parse(readFileSync(new URL('../vectors/jose-ml-dsa-65.json', import.meta.url), 'utf8'));
  const t = [v.trusted_public_key];
  assert.equal(verifyProfile('jose-ml-dsa-65', v.valid, { trustedKeys: t }).valid, true);
  assert.equal(verifyProfile('jose-ml-dsa-65', { ...v.valid, jws: v.valid.jws + '\n' }, { trustedKeys: t }).valid, false);
  assert.equal(verifyProfile('jose-ml-dsa-65', { ...v.valid, jws: [v.valid.jws] }, { trustedKeys: t }).valid, false);
  const [h, p, s] = v.valid.jws.split('.');
  assert.equal(verifyProfile('jose-ml-dsa-65', { ...v.valid, jws: `${Buffer.from([0xff, 0xfe]).toString('base64url')}.${p}.${s}` }, { trustedKeys: t }).valid, false);
  const xs = JSON.parse(readFileSync(new URL('../vectors/x402-served.json', import.meta.url), 'utf8'));
  assert.equal(verifyProfile('x402-served', { ...xs.valid, route_id: [xs.valid.route_id] }, { trustedKeys: [xs.trusted_public_key] }).valid, false);
  assert.equal(verifyProfile('x402-served', { ...xs.valid, profile: 'sar' }, { trustedKeys: [xs.trusted_public_key] }).valid, false);
  assert.equal(verifyProfile('x402-served', { ...xs.valid, signature: xs.valid.signature + '\n' }, { trustedKeys: [xs.trusted_public_key] }).valid, false);
});
