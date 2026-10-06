/**
 * The referee. One verify function per PQC agent-receipt profile — what a contributor to any hot
 * standard (A2A, x402, AP2, W3C VC, IETF COSE Receipts) runs to claim "PQC-receipt conformant".
 * Every check is OFFLINE with the audited @noble/post-quantum ml_dsa65 — talks to nobody.
 *
 * TRUST MODEL (hardened after red-team C1): a signature that verifies proves only that SOME key signed
 * these bytes — NOT that FractalAI did. Authenticity requires binding the signing key to an anchored
 * identity. So verifyProfile is FAIL-CLOSED: `valid` is true only when the signature verifies AND the
 * embedded public key is in the caller-supplied `trustedKeys` (e.g. the keys published at
 * /.well-known/x402-receipt-keys, ideally on-chain-anchored). With no trustedKeys the result is
 * `valid:false, keyTrusted:false` and `signatureValid` tells you the signature-over-bytes held — i.e.
 * "authorship UNVERIFIED", never a green check for a self-signed forgery.
 *
 * Profiles (all ML-DSA-65 / FIPS-204): x402-served, sar, acp-verdict, jose-ml-dsa-65, vc-di-ml-dsa-65,
 * hai-ml-dsa-65, a2a-receipt-ml-dsa-65.
 * Honest scope: attests authorship + integrity of the bytes (non-repudiation), not that the underlying
 * action/content is "correct"; uses the FIPS-204 algorithm via an audited library, not a CMVP module.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';

const utf8 = (s) => new TextEncoder().encode(s);
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

// Strict base64 / base64url (red-team L6): reject non-canonical encodings (whitespace, wrong alphabet,
// bad padding) so a signature string can't be malleated while still "verifying".
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;
const B64URL = /^[A-Za-z0-9_-]*={0,2}$/;
function strictB64(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !B64.test(s)) throw new Error('non-canonical base64');
  return new Uint8Array(Buffer.from(s, 'base64'));
}
function strictB64url(s) {
  if (typeof s !== 'string' || !B64URL.test(s)) throw new Error('non-canonical base64url');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64'));
}

/** RFC 8785-style JCS over the integer/string value space these receipts use. Throws on non-finite
 * numbers (RFC 8785 forbids them; red-team L4: NaN/Infinity → null made jcs non-injective). NOTE: not a
 * full RFC 8785 number serializer (exponent forms like 1e21 differ) — keep receipt values to integers
 * and strings, or plug a full RFC 8785 lib for cross-impl byte-parity. */
export function jcs(v) {
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('JCS: non-finite number (NaN/Infinity forbidden by RFC 8785)');
    return JSON.stringify(v);
  }
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  throw new Error(`JCS: unsupported ${typeof v}`);
}

function sizeError(sig, pk) {
  if (pk.length !== 1952) return `public key is ${pk.length} bytes, not 1952 (not ML-DSA-65)`;
  if (sig.length !== 3309) return `signature is ${sig.length} bytes, not 3309 (not ML-DSA-65)`;
  return null;
}

// Each profile checker returns { signatureValid, publicKeyB64, reason } (no key-trust — that's central).
const CHECKERS = {
  'x402-served'(e) {
    // H3: this generic route MUST NOT carry the reserved acp-verdict route (else one sig = two meanings).
    if (e.route_id === 'x402-attest-decision') return { signatureValid: false, reason: "route 'x402-attest-decision' is reserved for the acp-verdict profile — refuse cross-profile use" };
    const sig = strictB64(e.signature), pk = strictB64(e.public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    const expected = `${e.domain}\n${e.route_id}\n${e.digest}`;
    if (e.signed_message !== expected) return { signatureValid: false, reason: 'signed_message != domain\\nroute\\ndigest (non-canonical)' };
    return { signatureValid: ml_dsa65.verify(sig, utf8(e.signed_message), pk) === true, publicKeyB64: e.public_key, reason: 'x402-served' };
  },
  'sar'(e) {
    const sig = strictB64(e.signature), pk = strictB64(e.public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    const { signatures, ...core } = e.sar || {};
    const expected = `x402-sar-pqc-v1\n${sha256hex(jcs(core))}`;
    if (e.signed_message !== expected) return { signatureValid: false, reason: 'signed_message != x402-sar-pqc-v1\\nsha256(JCS(core)) — tampered/non-canonical' };
    return { signatureValid: ml_dsa65.verify(sig, utf8(e.signed_message), pk) === true, publicKeyB64: e.public_key, reason: 'sar' };
  },
  'acp-verdict'(e) {
    const sig = strictB64(e.signature), pk = strictB64(e.public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    const expected = `FRACTALAI-x402-served-v1\nx402-attest-decision\n${sha256hex(jcs(e.decision))}`;
    if (e.signed_message !== expected) return { signatureValid: false, reason: 'signed_message != served proof over sha256(JCS(decision))' };
    return { signatureValid: ml_dsa65.verify(sig, utf8(e.signed_message), pk) === true, publicKeyB64: e.public_key, reason: 'acp-verdict' };
  },
  'vc-di-ml-dsa-65'(e) {
    const doc = e.securedDocument;
    if (!doc || !doc.proof) return { signatureValid: false, reason: 'no DataIntegrityProof on the credential' };
    const { proof, ...unsecured } = doc;
    if (proof.type !== 'DataIntegrityProof') return { signatureValid: false, reason: `proof.type is '${proof.type}', expected DataIntegrityProof` };
    if (proof.cryptosuite !== 'mldsa65-jcs-2024') return { signatureValid: false, reason: `cryptosuite is '${proof.cryptosuite}', expected mldsa65-jcs-2024` };
    const { proofValue, ...proofConfig } = proof;
    if (typeof proofValue !== 'string' || proofValue[0] !== 'u') return { signatureValid: false, reason: 'proofValue must be multibase base64url (u-prefixed)' };
    const sig = strictB64url(proofValue.slice(1)), pk = strictB64(e.public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    const hashData = Buffer.concat([
      createHash('sha256').update(jcs(proofConfig), 'utf8').digest(),
      createHash('sha256').update(jcs(unsecured), 'utf8').digest(),
    ]);
    return { signatureValid: ml_dsa65.verify(sig, new Uint8Array(hashData), pk) === true, publicKeyB64: e.public_key, reason: 'vc-di' };
  },
  'jose-ml-dsa-65'(e) {
    const parts = String(e.jws).split('.');
    if (parts.length !== 3) return { signatureValid: false, reason: 'not a compact JWS (need 3 dot-separated parts)' };
    const [h, p, s] = parts;
    let header; try { header = JSON.parse(Buffer.from(h.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch { return { signatureValid: false, reason: 'bad JWS header' }; }
    if (header.alg !== 'ML-DSA-65') return { signatureValid: false, reason: `JOSE alg is '${header.alg}', expected 'ML-DSA-65' (RFC 9964)` };
    const sig = strictB64url(s), pk = strictB64(e.public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    return { signatureValid: ml_dsa65.verify(sig, utf8(`${h}.${p}`), pk) === true, publicKeyB64: e.public_key, reason: 'jose' };
  },
  // Post-quantum extension of Corrente Labs' Hardware-Attested Agent Identity (HAI) strawman
  // (x402-foundation/wg-identity#27, section 3.1) — additive, not a replacement: their `identity`
  // object still carries the TEE hardware quote (Intel TDX / AMD SEV-SNP) unchanged; this profile
  // covers only the case where `identity.format` opts into an ML-DSA-65 signature bound to the
  // SAME publicKey/timestamp/nonce fields their spec already defines, giving a software-only PQC
  // path for the many agents that have no TEE. Domain-separated so a HAI signature can never be
  // replayed as one of this package's other profiles.
  'hai-ml-dsa-65'(e) {
    if (e.identity?.format !== 'eat+cwt+ml-dsa-65') return { signatureValid: false, reason: `identity.format is '${e.identity?.format}', expected 'eat+cwt+ml-dsa-65'` };
    const pqc = e.identity.pqc || {};
    if (pqc.algorithm !== 'ml-dsa-65') return { signatureValid: false, reason: `identity.pqc.algorithm is '${pqc.algorithm}', expected 'ml-dsa-65'` };
    const sig = strictB64(pqc.signature), pk = strictB64(pqc.public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    const core = { publicKey: e.identity.publicKey, timestamp: e.identity.timestamp, nonce: e.identity.nonce };
    const expected = `FRACTALAI-hai-pqc-v1\n${sha256hex(jcs(core))}`;
    if (pqc.signed_message !== expected) return { signatureValid: false, reason: 'signed_message != FRACTALAI-hai-pqc-v1\\nsha256(JCS({publicKey,timestamp,nonce})) — tampered/non-canonical' };
    return { signatureValid: ml_dsa65.verify(sig, utf8(pqc.signed_message), pk) === true, publicKeyB64: pqc.public_key, reason: 'hai' };
  },
  // Post-quantum algorithm option for CSOAI's `signed-receipts/v1` A2A extension proposal
  // (a2aproject/A2A#2150; spec+reference impl: github.com/CSOAI-ORG/a2a-signed-receipts). Their
  // reference signs Ed25519 over the RFC-8785-canonical receipt object (content_id included); this
  // profile is the SAME wire shape and SAME signing procedure with `signature.alg: "ML-DSA-65"` and
  // signer_public_key/sig re-encoded as base64 (vs. their hex) — an issuer picks one alg, not both.
  // `content_id` is a redundant integrity anchor per their own spec (sha256 of the body minus itself
  // and minus signature); we verify it AND the signature, so a mismatched content_id fails loud
  // rather than only surfacing as a downstream signature failure.
  'a2a-receipt-ml-dsa-65'(e) {
    const receipt = e.receipt;
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return { signatureValid: false, reason: 'no receipt object' };
    if (receipt.schema !== 'a2a.signed-receipt/0.1') return { signatureValid: false, reason: `schema is '${receipt.schema}', expected 'a2a.signed-receipt/0.1'` };
    const { signature, ...body } = receipt;
    if (!signature || signature.alg !== 'ML-DSA-65') return { signatureValid: false, reason: `signature.alg is '${signature?.alg}', expected 'ML-DSA-65'` };
    const sig = strictB64(signature.sig), pk = strictB64(signature.signer_public_key);
    const sz = sizeError(sig, pk); if (sz) return { signatureValid: false, reason: sz };
    const { content_id, ...unsigned } = body;
    if (typeof content_id !== 'string' || content_id !== sha256hex(jcs(unsigned))) return { signatureValid: false, reason: 'content_id != sha256(JCS(receipt minus content_id/signature)) — tampered/non-canonical' };
    return { signatureValid: ml_dsa65.verify(sig, utf8(jcs(body)), pk) === true, publicKeyB64: signature.signer_public_key, reason: 'a2a-signed-receipt' };
  },
};

export const PROFILES = Object.keys(CHECKERS);

/**
 * Verify one receipt against its profile, FAIL-CLOSED on key provenance.
 * @param opts.trustedKeys array of base64 ML-DSA-65 public keys that count as authentic (e.g. from the
 *   anchored key directory). Omit → keyTrusted:false (authorship unverified), valid:false.
 * @returns { valid, signatureValid, keyTrusted, reason } — valid === signatureValid && keyTrusted.
 */
export function verifyProfile(profile, entry, opts = {}) {
  const c = CHECKERS[profile];
  if (!c) return { valid: false, signatureValid: false, keyTrusted: false, reason: `unknown profile '${profile}'` };
  let r;
  try { r = c(entry); } catch (e) { return { valid: false, signatureValid: false, keyTrusted: false, reason: `verify error: ${e instanceof Error ? e.message : String(e)}` }; }
  const signatureValid = r.signatureValid === true;
  const trusted = Array.isArray(opts.trustedKeys) ? opts.trustedKeys : null;
  const keyTrusted = signatureValid && !!trusted && !!r.publicKeyB64 && trusted.includes(r.publicKeyB64);
  let reason;
  if (!signatureValid) reason = `signature INVALID (${r.reason})`;
  else if (!trusted) reason = `signature verifies over the bytes, but no trustedKeys supplied — authorship UNVERIFIED (a self-signed forgery reaches here)`;
  else if (!keyTrusted) reason = `signature verifies, but the signing key is NOT in the trusted set — untrusted key (likely forgery)`;
  else reason = `authentic: ML-DSA-65 signature by a trusted key over the exact ${profile} bytes`;
  return { valid: signatureValid && keyTrusted, signatureValid, keyTrusted, reason };
}
