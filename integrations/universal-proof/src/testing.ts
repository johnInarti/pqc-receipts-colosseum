/**
 * TEST PKI ONLY — deterministic ML-DSA-65 keys, a test key directory that lists a `commerce-receipt` key, and test
 * trust roots. The kernel reports these as an OVERRIDE (`trust_basis: "override"`); they are never trusted by the
 * baked production roots. Production needs FractalAI's governance key to publish a `commerce-receipt` key in a new
 * directory epoch (a founder decision, see README).
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256hex, kidForKey, b64encode, directoryRoot, KEY_DIR_DOMAIN, BAKED_ROOTS } from '@fractalai/pqc-trust-kernel';
import { localSigner, utf8 } from './core.ts';
import type { Signer } from './core.ts';

export interface TestKey { tag: string; pk: string; kid: string; secretKey: Uint8Array; publicKey: Uint8Array; signer: Signer }

export function testKey(tag: string): TestKey {
  const h = sha256hex(`fractalai-universal-proof-test-seed/${tag}`);
  const seed = Uint8Array.from(h.match(/../g)!.slice(0, 32).map((x) => parseInt(x, 16)));
  const kp = ml_dsa65.keygen(seed);
  const pk = b64encode(kp.publicKey);
  return { tag, pk, kid: kidForKey(pk), secretKey: kp.secretKey, publicKey: kp.publicKey, signer: localSigner(kp.secretKey, kp.publicKey, { deterministic: true }) };
}

export interface DirEntry { key: TestKey; use: string; status: string; not_before?: number | null; not_after?: number | null }

export function testDirectory(entries: DirEntry[], gov: TestKey, epoch = 1, prevRoot = '0'.repeat(64)) {
  const keys = entries.map((e) => ({
    kid: e.key.kid, use: e.use, algorithm: 'ML-DSA-65 (FIPS-204)', public_key_b64: e.key.pk, added_at: 0,
    status: e.status, not_before: e.not_before ?? null, not_after: e.not_after ?? null,
  }));
  const root = directoryRoot(keys, prevRoot, epoch, gov.pk);
  const signed_message = `${KEY_DIR_DOMAIN}\n${root}`;
  const sig = ml_dsa65.sign(utf8(signed_message), gov.secretKey, { extraEntropy: false });
  return { spec: KEY_DIR_DOMAIN, issuer: 'universal-proof TEST directory', epoch, prev_root: prevRoot, root, keys, signed_message, signature: b64encode(sig), directory_public_key: gov.pk };
}

export function testRoots(gov: TestKey, dir: { epoch: number; root: string; prev_root: string }) {
  const r = JSON.parse(JSON.stringify(BAKED_ROOTS));
  r.issuer = 'universal-proof TEST roots (never baked)';
  r.governance = { ...r.governance, public_key_b64: gov.pk, kid: gov.kid };
  r.directory_checkpoint = { ...r.directory_checkpoint, epoch: dir.epoch, root: dir.root, prev_root: dir.prev_root, known_previous_roots: {} };
  return r;
}

/** A ready-made test trust context: issuer key with use `commerce-receipt`, plus an x402-only key for negatives. */
export function testTrust() {
  const gov = testKey('governance');
  const issuer = testKey('commerce-issuer');
  const x402Only = testKey('x402-only');
  const directory = testDirectory([
    { key: issuer, use: 'commerce-receipt', status: 'active', not_before: 1790000000 },
    { key: x402Only, use: 'x402-receipt', status: 'active', not_before: 1790000000 },
  ], gov);
  const roots = testRoots(gov, directory);
  return { gov, issuer, x402Only, directory, roots, opts: { roots, directory: JSON.stringify(directory) } };
}
