#!/usr/bin/env node
/**
 * verify-x402-receipt-signer.mjs — durable verification of the x402 receipt ML-DSA-65 (FIPS 204)
 * signer's crypto operations. Mirrors lib/x402-receipt-signer.ts exactly (seed hex→32B, keygen,
 * sign(msg, secretKey), base64, verify(sig, msg, publicKey)). Run: `cd frontend && node scripts/verify-x402-receipt-signer.mjs`.
 *
 * Exists because @noble/post-quantum is ESM-only and next/jest overrides transformIgnorePatterns,
 * so the crypto can't be exercised under the current jest setup. This node ESM script can.
 * @noble API order verified empirically 2026-08-07: sign(message, secretKey); verify(signature, message, publicKey).
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const seedHex = 'ab'.repeat(32);
const seed = new Uint8Array(32);
for (let i = 0; i < 32; i++) seed[i] = parseInt(seedHex.substring(i * 2, i * 2 + 2), 16);
const kp = ml_dsa65.keygen(seed);

const sign = (c) => {
  const sig = ml_dsa65.sign(new TextEncoder().encode(c), kp.secretKey);
  return {
    pqc_signature: Buffer.from(sig).toString('base64'),
    signature_algorithm: 'ml-dsa-65',
    pqc_public_key: Buffer.from(kp.publicKey).toString('base64'),
  };
};
const verify = (c, sigB64, pkB64) => {
  try {
    return ml_dsa65.verify(
      Uint8Array.from(Buffer.from(sigB64, 'base64')),
      new TextEncoder().encode(c),
      Uint8Array.from(Buffer.from(pkB64, 'base64')),
    );
  } catch {
    return false;
  }
};

const canonical = 'x402-receipt-v1|service=x402-sign|payment=aa|request=bb|result=cc|ts=1000';
const s = sign(canonical);
const checks = [
  ['algorithm ml-dsa-65', s.signature_algorithm === 'ml-dsa-65'],
  ['signature 3309 B (FIPS-204)', Buffer.from(s.pqc_signature, 'base64').length === 3309],
  ['public key 1952 B (FIPS-204)', Buffer.from(s.pqc_public_key, 'base64').length === 1952],
  ['roundtrip verify true', verify(canonical, s.pqc_signature, s.pqc_public_key) === true],
  ['tampered payload verify false', verify(canonical + 'X', s.pqc_signature, s.pqc_public_key) === false],
  ['malformed key no-throw false', verify(canonical, s.pqc_signature, 'deadbeef') === false],
  ['deterministic (stable pubkey)', sign(canonical).pqc_public_key === s.pqc_public_key],
  ['distinct payload distinct sig', sign(canonical + '|x=1').pqc_signature !== s.pqc_signature],
];

let all = true;
for (const [name, pass] of checks) {
  console.log((pass ? '✅' : '❌') + ' ' + name);
  if (!pass) all = false;
}
console.log('\n' + (all ? '🎯 x402 receipt ML-DSA-65 signer verified' : '⚠️ VERIFICATION FAILED'));
process.exit(all ? 0 : 1);
