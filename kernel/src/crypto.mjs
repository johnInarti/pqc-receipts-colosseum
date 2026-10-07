/**
 * The only cryptographic primitives the kernel uses, all from the @noble family (audited, pure JS):
 *   ML-DSA-65 (FIPS 204) verify — receipts and the key directory,
 *   SHA-256 — content ids, receipt ids, kids, directory roots,
 *   Keccak-256 — EVM runtime code hash,
 *   Ed25519 verify — Solana transaction signer (checked locally, never trusted from the RPC).
 * NOT a CMVP/FIPS 140-3 validated module (spec §2, limits).
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { utf8 } from './canon.mjs';
import { bytesToHex } from './hygiene.mjs';

export const ML_DSA_65_PK_BYTES = 1952;
export const ML_DSA_65_SIG_BYTES = 3309;

const toBytes = (d) => (typeof d === 'string' ? utf8(d) : d);
export const sha256 = (d) => nobleSha256(toBytes(d));
export const sha256hex = (d) => bytesToHex(sha256(d));
export const keccak256hex = (bytes) => '0x' + bytesToHex(keccak_256(bytes));

/** kid = sha256(canonical base64 text of the public key)[:16 hex] — binds a label to exactly one key. */
export const kidForKey = (publicKeyB64) => sha256hex(publicKeyB64).slice(0, 16);

/** ML-DSA-65 verify, pure FIPS 204 (empty context). Never throws: malformed inputs → false. */
export function mldsaVerify(sigBytes, message, pkBytes) {
  try {
    if (sigBytes.length !== ML_DSA_65_SIG_BYTES || pkBytes.length !== ML_DSA_65_PK_BYTES) return false;
    return ml_dsa65.verify(sigBytes, toBytes(message), pkBytes) === true;
  } catch {
    return false;
  }
}

/** Ed25519 verify (RFC 8032, strict: noble rejects non-canonical S / small-order keys by default in zip215:false). */
export function ed25519Verify(sig64, message, pub32) {
  try {
    return ed25519.verify(sig64, message, pub32, { zip215: false }) === true;
  } catch {
    return false;
  }
}
