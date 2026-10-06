/**
 * Key Transparency for PQC agent-receipt keys — the trust ROOT the red-team C1 fix depends on.
 *
 * A receipt verifier is only fail-closed-useful if the caller has an AUTHENTIC set of trusted keys.
 * Today those come from /.well-known/x402-receipt-keys over TLS — self-asserted. This makes the
 * directory itself a verifiable object: it is (1) ML-DSA-65 SIGNED by a governance key, (2) APPEND-ONLY
 * and CHAINED (each epoch commits to the previous root, so key additions/rotations are non-repudiable
 * and equivocation is detectable — CT/CONIKS applied to agent keys), and (3) ANCHORABLE — its `root`
 * is exactly what goes on-chain (FractalCheckpoint), so an offline verifier can confirm the key set
 * WITHOUT trusting FractalAI's TLS: it checks the directory signature AND that `root` equals the value
 * anchored on Base.
 *
 * Honest scope: this binds "which keys are authentic" to a signed, append-only, anchorable log — it does
 * not by itself prove the governance key is FractalAI's (that trust root is the on-chain anchor / a
 * published governance key). Offline; @noble only; no network.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import { jcs } from './profiles.mjs';

const utf8 = (s) => new TextEncoder().encode(s);
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
export const KEY_DIR_DOMAIN = 'FRACTALAI-key-directory-v1';
const Z = '0'.repeat(64);

/** The kid MUST be sha256(public_key_b64)[:16] so a `kid` label can't alias/substitute a real key
 * (red-team C2). Used to enforce the binding in verifyDirectory + to mint kids in the route. */
export const kidForKey = (publicKeyB64) => sha256hex(publicKeyB64).slice(0, 16);

/** Canonical root over the epoch's committed content. Commits the FULL key objects (red-team M1) AND
 * the governance signer (red-team M2) AND the chain (prev_root), so the anchored root binds who signed
 * and every trust-relevant key field — not just a 4-field subset. */
export function directoryRoot(keys, prevRoot, epoch, governanceKeyB64) {
  const canonicalKeys = [...keys].sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
  return sha256hex(jcs({ epoch, prev_root: prevRoot || Z, governance_key: governanceKeyB64 || null, keys: canonicalKeys }));
}

/** Build a signed directory epoch. `seedHex` is the GOVERNANCE key (distinct from receipt keys). */
export function buildDirectory(keys, seedHex, { epoch = 1, prevRoot = Z } = {}) {
  const h = seedHex.trim();
  if (h.length !== 64 || !/^[0-9a-fA-F]+$/.test(h)) throw new Error('governance seed must be 64 hex chars');
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  const kp = ml_dsa65.keygen(seed);
  const governanceKeyB64 = Buffer.from(kp.publicKey).toString('base64');
  const root = directoryRoot(keys, prevRoot, epoch, governanceKeyB64);
  const signedMessage = `${KEY_DIR_DOMAIN}\n${root}`;
  const signature = Buffer.from(ml_dsa65.sign(utf8(signedMessage), kp.secretKey, { extraEntropy: false })).toString('base64');
  return {
    spec: KEY_DIR_DOMAIN, epoch, prev_root: prevRoot, root, keys,
    signed_message: signedMessage, signature,
    directory_public_key: Buffer.from(kp.publicKey).toString('base64'),
  };
}

/**
 * Verify a directory epoch OFFLINE. FAIL-CLOSED:
 *  - the governance signature must verify over `KEY_DIR_DOMAIN\n<root>`;
 *  - `root` must equal the recomputed root over its keys/prev_root/epoch (no tampered key set);
 *  - if `governanceKey` is supplied, the directory's signer MUST equal it (pin the governance identity);
 *  - if `anchoredRoot` is supplied, `root` MUST equal it (the on-chain commitment — trustless of TLS);
 *  - if `expectedPrevRoot` is supplied, the chain must be continuous (non-equivocation across epochs).
 * @returns { valid, reason, trustedKeys } — trustedKeys is [] unless valid.
 */
export function verifyDirectory(dir, opts = {}) {
  const NO = (reason, signatureValid = false) => ({ valid: false, signatureValid, reason, trustedKeys: [] });
  try {
    if (dir.spec !== KEY_DIR_DOMAIN) return NO(`not a ${KEY_DIR_DOMAIN} directory`);
    const pk = new Uint8Array(Buffer.from(dir.directory_public_key, 'base64'));
    const sig = new Uint8Array(Buffer.from(dir.signature, 'base64'));
    if (pk.length !== 1952) return NO('governance public key is not 1952 bytes (not ML-DSA-65)');
    if (sig.length !== 3309) return NO('governance signature is not 3309 bytes (not ML-DSA-65)');
    // C2: every kid MUST be sha256(pubkey)[:16] — a `kid` can't alias/substitute a real key.
    for (const k of (dir.keys || [])) {
      if (k.kid !== kidForKey(k.public_key_b64)) return NO(`kid ${k.kid} != sha256(public_key)[:16] — forged/aliased kid`);
    }
    // Root now commits the governance signer (M2) + full key objects (M1) + chain.
    const recomputed = directoryRoot(dir.keys, dir.prev_root, dir.epoch, dir.directory_public_key);
    if (recomputed !== dir.root) return NO('directory root != recomputed root (keys/governance/chain) — tampered');
    if (dir.signed_message !== `${KEY_DIR_DOMAIN}\n${dir.root}`) return NO('signed_message != domain\\nroot — non-canonical');
    if (ml_dsa65.verify(sig, utf8(dir.signed_message), pk) !== true) return NO('governance signature does not verify');
    // — signature + root + kid binding are all valid from here (signatureValid = true) —
    if (opts.governanceKey && opts.governanceKey !== dir.directory_public_key) return NO('directory signer != pinned governance key — untrusted directory', true);
    if (opts.anchoredRoot && opts.anchoredRoot.toLowerCase() !== dir.root.toLowerCase()) return NO('directory root != on-chain anchored root — possible equivocation, refuse', true);
    if (opts.expectedPrevRoot && (dir.prev_root || Z).toLowerCase() !== opts.expectedPrevRoot.toLowerCase()) return NO('prev_root does not chain to the expected previous epoch — discontinuity', true);
    // H1 FAIL-CLOSED (parity with profiles.mjs): a self-signed directory proves NOTHING about WHO signed.
    // Authenticity requires pinning the governance key OR matching the on-chain anchored root.
    if (!opts.governanceKey && !opts.anchoredRoot) {
      return { valid: false, signatureValid: true, reason: 'directory signature verifies but the signer is UNVERIFIED — supply a pinned governanceKey or an anchoredRoot (a self-signed directory is not trust)', trustedKeys: [] };
    }
    return { valid: true, signatureValid: true, reason: 'authentic: ML-DSA-65-signed directory by a ' + (opts.governanceKey ? 'pinned governance key' : 'signer whose root matches the on-chain anchor') + '; root recomputes', trustedKeys: dir.keys.map((k) => k.public_key_b64) };
  } catch (e) {
    return NO(`verify error: ${e instanceof Error ? e.message : String(e)}`);
  }
}
