#!/usr/bin/env node
/**
 * The conformance checker — run this to claim "PQC agent-receipt conformant". For every profile it
 * proves the verifier is FAIL-CLOSED on authenticity (red-team C1), not just a signature check:
 *   - genuine  (issuer key, pinned as trusted) → valid:true   (authentic)
 *   - tampered (issuer key, flipped/edited)     → valid:false  (signature invalid)
 *   - forged   (attacker key + own content)     → valid:false  (signature verifies but key UNTRUSTED)
 * It also asserts the fail-closed default: with NO trusted key, even the genuine receipt is valid:false
 * (authorship unverified) — a self-signed blob never gets a green check. Pure @noble; offline.
 *
 *   node src/check.mjs [vectorsDir]     (default: ../vectors)
 * Exit 0 iff every profile passes all four assertions.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { parseJsonStrict } from '@fractalai/pqc-trust-kernel';
import { verifyProfile, PROFILES } from './profiles.mjs';

const dir = new URL((process.argv[2] ? process.argv[2].replace(/\/?$/, '/') : '../vectors/'), import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith('.json'));

let pass = 0, fail = 0;
const rows = [];
for (const f of files) {
  let v;
  try { v = parseJsonStrict(readFileSync(new URL(f, dir), 'utf8')); } catch (e) { rows.push({ profile: f, ok: false }); fail++; continue; }
  const profile = v.profile;
  const trusted = [v.trusted_public_key];
  // Authentic: genuine receipt with the trusted key pinned.
  const genuine = verifyProfile(profile, v.valid, { trustedKeys: trusted }).valid === true;
  // Fail-closed default: same genuine receipt, but NO trusted key → must NOT be valid.
  const failClosed = verifyProfile(profile, v.valid).valid === false;
  // Tampered signature/content → rejected.
  const tamperRejected = verifyProfile(profile, v.tampered, { trustedKeys: trusted }).valid === false;
  // Different-key forgery → rejected even though its signature verifies over its own bytes.
  const fr = verifyProfile(profile, v.forged, { trustedKeys: trusted });
  const forgeRejected = fr.valid === false && fr.signatureValid === true; // sig valid, but key untrusted
  const ok = genuine && failClosed && tamperRejected && forgeRejected;
  ok ? pass++ : fail++;
  rows.push({ profile, genuine, failClosed, tamperRejected, forgeRejected, ok });
}

const pad = (s, n) => String(s).padEnd(n);
const yn = (b) => (b ? 'PASS' : 'FAIL');
console.log(`\nPQC Agent-Receipt Conformance — ML-DSA-65 (FIPS-204), offline, FAIL-CLOSED on key provenance\n`);
console.log(pad('profile', 18), pad('authentic', 10), pad('fail-closed', 12), pad('tamper✗', 9), pad('forgery✗', 9), 'result');
console.log('-'.repeat(78));
for (const r of rows) console.log(pad(r.profile, 18), pad(yn(r.genuine), 10), pad(yn(r.failClosed), 12), pad(yn(r.tamperRejected), 9), pad(yn(r.forgeRejected), 9), r.ok ? 'OK' : '✗ FAIL');

// Fail closed (red-team poc6): an empty vector set, a missing profile, or a duplicated one is NOT conformance.
const missing = PROFILES.filter((p) => !rows.some((r) => r.profile === p && r.ok));
const dup = rows.length !== new Set(rows.map((r) => r.profile)).size;
if (missing.length) console.log(`\nprofiles with no passing vector: ${missing.join(', ')}`);
const conformant = fail === 0 && rows.length > 0 && missing.length === 0 && !dup;
console.log(`\n${conformant ? '✅ CONFORMANT' : '❌ NON-CONFORMANT'} — ${pass}/${PROFILES.length} profiles: accept genuine trusted key · reject no-trust · reject tamper · reject different-key forgery`);
process.exit(conformant ? 0 : 1);
