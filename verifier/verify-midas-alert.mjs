#!/usr/bin/env node
// Verify one FractalAI MIDAS signed alert receipt from outside, with no trust in FractalAI's TLS beyond
// fetching the public key directory (pin it after the first run if you prefer).
// usage: node verify-midas-alert.mjs [receipt_id]   (default: the public receipt fe62b072…)
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';

const id = process.argv[2] || 'fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee';
const base = process.env.FRACTALAI_BASE || 'https://fractalai.net.co';
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

const r = await (await fetch(`${base}/api/midas/alerts/receipt/${id}`)).json();
const dir = await (await fetch(`${base}/.well-known/x402-receipt-keys`)).json();

const checks = {
  receipt_id_is_sha256_of_canonical: sha(r.canonical) === r.receipt_id,
  domain_string_matches: r.served_message === `FRACTALAI-x402-served-v1\nmidas-alert\n${id}`,
  ml_dsa65_signature_valid: ml_dsa65.verify(
    Buffer.from(r.signature, 'base64'),
    new TextEncoder().encode(r.served_message),
    Buffer.from(r.public_key, 'base64'),
  ),
  key_in_directory_status: dir.keys.find((k) => k.public_key_b64 === r.public_key)?.status ?? 'NOT_FOUND',
  directory_epoch: dir.epoch,
};
console.log(JSON.stringify(checks, null, 2));
const ok = checks.receipt_id_is_sha256_of_canonical && checks.domain_string_matches && checks.ml_dsa65_signature_valid && checks.key_in_directory_status === 'active';
console.log(ok ? 'VALID (signature verified; key active in epoch-chained directory)' : 'INVALID or key not active');
process.exit(ok ? 0 : 1);
