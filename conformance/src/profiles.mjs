/**
 * The referee — one checker per PQC agent-receipt profile, all built on Trust Kernel v2 primitives
 * (strict base64 / JSON / JCS, ML-DSA-65 verify). FractalAI's own signed formats (x402-served,
 * acp-verdict) are not re-implemented here at all: they are DELEGATED to the kernel's kinds, so the
 * domain↔route binding has exactly one implementation.
 *
 * TRUST MODEL: a signature that verifies proves only that SOME key signed these bytes. `valid` is true only
 * when the signature verifies AND the embedded public key is in the caller's pinned `trustedKeys`
 * (an explicit pinned set — for FractalAI keys use the kernel with its pinned directory roots instead).
 * Strictness (python red-team N2): every field must already have the right JSON type — no String()
 * coercion of arrays/numbers, JOSE headers must be valid UTF-8 strict JSON, base64/base64url canonical.
 * Honest scope: authorship + integrity of bytes, not truth of content; @noble library, not a CMVP module.
 */
import {
  verifySync, jcs, sha256hex, utf8, mldsaVerify, b64decodeStrict, parseJsonStrict, assertJsonValue, KernelError,
  ML_DSA_65_PK_BYTES as PKB, ML_DSA_65_SIG_BYTES as SIGB,
} from '@fractalai/pqc-trust-kernel';

export { jcs };

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
/** Canonical unpadded base64url (RFC 7515 §2): fixed alphabet, no padding, no whitespace, zero pad bits. */
export function strictB64url(s, len) {
  if (typeof s !== 'string' || !B64URL_RE.test(s) || s.length % 4 === 1) throw new KernelError('B64_NONCANONICAL', 'non-canonical base64url');
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  return b64decodeStrict(padded, len, 'base64url value');
}
const str = (v, what) => { if (typeof v !== 'string') throw new KernelError('INPUT_SHAPE', `${what} must be a string`); return v; };
const obj = (v, what) => { if (!v || typeof v !== 'object' || Array.isArray(v)) throw new KernelError('INPUT_SHAPE', `${what} must be an object`); return v; };
const bad = (reason) => ({ signatureValid: false, reason });

/** Kernel-delegated profiles: signature validity == kernel `authentic` for that kind. */
function viaKernel(kind) {
  return (e) => {
    const v = verifySync(JSON.stringify(e), { kind, trustedKeys: JSON.stringify(['_']) });
    return { signatureValid: v.levels.authentic === true, publicKeyB64: typeof e.public_key === 'string' ? e.public_key : undefined, reason: v.levels.authentic ? kind : `${v.reasons[0]?.code}: ${v.reasons[0]?.detail}` };
  };
}

const CHECKERS = {
  'x402-served': viaKernel('served-proof'),
  'acp-verdict': viaKernel('acp-verdict'),
  'sar'(e) {
    const sig = b64decodeStrict(str(e.signature, 'signature'), SIGB, 'signature'), pk = b64decodeStrict(str(e.public_key, 'public_key'), PKB, 'public_key');
    const { signatures, ...core } = obj(e.sar, 'sar');
    const expected = `x402-sar-pqc-v1\n${sha256hex(jcs(core))}`;
    if (str(e.signed_message, 'signed_message') !== expected) return bad('signed_message != x402-sar-pqc-v1\\nsha256(JCS(core))');
    return { signatureValid: mldsaVerify(sig, utf8(expected), pk), publicKeyB64: e.public_key, reason: 'sar' };
  },
  'vc-di-ml-dsa-65'(e) {
    const doc = obj(e.securedDocument, 'securedDocument');
    const { proof, ...unsecured } = doc;
    obj(proof, 'proof');
    if (proof.type !== 'DataIntegrityProof') return bad(`proof.type is not DataIntegrityProof`);
    if (proof.cryptosuite !== 'mldsa65-jcs-2024') return bad('cryptosuite is not mldsa65-jcs-2024');
    const { proofValue, ...proofConfig } = proof;
    if (typeof proofValue !== 'string' || proofValue[0] !== 'u') return bad('proofValue must be multibase base64url (u-prefixed)');
    const sig = strictB64url(proofValue.slice(1), SIGB), pk = b64decodeStrict(str(e.public_key, 'public_key'), PKB, 'public_key');
    const hashData = new Uint8Array([...Buffer.from(sha256hex(jcs(proofConfig)), 'hex'), ...Buffer.from(sha256hex(jcs(unsecured)), 'hex')]);
    return { signatureValid: mldsaVerify(sig, hashData, pk), publicKeyB64: e.public_key, reason: 'vc-di' };
  },
  'jose-ml-dsa-65'(e) {
    const parts = str(e.jws, 'jws').split('.');
    if (parts.length !== 3) return bad('not a compact JWS (need 3 dot-separated parts)');
    const [h, p, s] = parts;
    let header;
    try { header = parseJsonStrict(new TextDecoder('utf-8', { fatal: true }).decode(strictB64url(h))); } catch { return bad('JWS header is not canonical base64url of strict UTF-8 JSON'); }
    if (!header || typeof header !== 'object' || header.alg !== 'ML-DSA-65') return bad(`JOSE alg is not ML-DSA-65 (RFC 9964)`);
    strictB64url(p);
    const sig = strictB64url(s, SIGB), pk = b64decodeStrict(str(e.public_key, 'public_key'), PKB, 'public_key');
    return { signatureValid: mldsaVerify(sig, utf8(`${h}.${p}`), pk), publicKeyB64: e.public_key, reason: 'jose' };
  },
  // PQC extension of Corrente Labs' HAI (x402-foundation/wg-identity#27 §3.1): ML-DSA-65 over the same
  // publicKey/timestamp/nonce fields the TEE path binds; domain-separated (FRACTALAI-hai-pqc-v1).
  'hai-ml-dsa-65'(e) {
    const id = obj(e.identity, 'identity');
    if (id.format !== 'eat+cwt+ml-dsa-65') return bad(`identity.format is not eat+cwt+ml-dsa-65`);
    const pqc = obj(id.pqc, 'identity.pqc');
    if (pqc.algorithm !== 'ml-dsa-65') return bad('identity.pqc.algorithm is not ml-dsa-65');
    const sig = b64decodeStrict(str(pqc.signature, 'signature'), SIGB, 'signature'), pk = b64decodeStrict(str(pqc.public_key, 'public_key'), PKB, 'public_key');
    const core = { publicKey: id.publicKey, timestamp: id.timestamp, nonce: id.nonce };
    const expected = `FRACTALAI-hai-pqc-v1\n${sha256hex(jcs(core))}`;
    if (str(pqc.signed_message, 'signed_message') !== expected) return bad('signed_message != FRACTALAI-hai-pqc-v1\\nsha256(JCS({publicKey,timestamp,nonce}))');
    return { signatureValid: mldsaVerify(sig, utf8(expected), pk), publicKeyB64: pqc.public_key, reason: 'hai' };
  },
  // PQC option for CSOAI signed-receipts/v1 (a2aproject/A2A#2150): same wire shape, alg ML-DSA-65, base64 key/sig.
  'a2a-receipt-ml-dsa-65'(e) {
    const receipt = obj(e.receipt, 'receipt');
    if (receipt.schema !== 'a2a.signed-receipt/0.1') return bad(`schema is not a2a.signed-receipt/0.1`);
    const { signature, ...body } = receipt;
    obj(signature, 'signature');
    if (signature.alg !== 'ML-DSA-65') return bad('signature.alg is not ML-DSA-65');
    const sig = b64decodeStrict(str(signature.sig, 'sig'), SIGB, 'sig'), pk = b64decodeStrict(str(signature.signer_public_key, 'signer_public_key'), PKB, 'signer_public_key');
    const { content_id, ...unsigned } = body;
    if (typeof content_id !== 'string' || content_id !== sha256hex(jcs(unsigned))) return bad('content_id != sha256(JCS(receipt minus content_id/signature))');
    return { signatureValid: mldsaVerify(sig, utf8(jcs(body)), pk), publicKeyB64: signature.signer_public_key, reason: 'a2a-signed-receipt' };
  },
};

export const PROFILES = Object.keys(CHECKERS);

/**
 * Verify one receipt against its profile, FAIL-CLOSED on key provenance.
 * @param opts.trustedKeys pinned base64 ML-DSA-65 public keys. Omit → valid:false (authorship unverified).
 * @returns { valid, signatureValid, keyTrusted, reason } — valid === signatureValid && keyTrusted. Never throws.
 */
export function verifyProfile(profile, entry, opts = {}) {
  const c = Object.prototype.hasOwnProperty.call(CHECKERS, profile) ? CHECKERS[profile] : null;
  if (!c) return { valid: false, signatureValid: false, keyTrusted: false, reason: `unknown profile '${profile}'` };
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return { valid: false, signatureValid: false, keyTrusted: false, reason: 'entry is not an object' };
  if (entry.profile !== undefined && entry.profile !== profile) return { valid: false, signatureValid: false, keyTrusted: false, reason: `entry.profile '${String(entry.profile).slice(0, 40)}' != '${profile}' (the caller fixes the profile, never the document)` };
  let r;
  try {
    // Defensive copy through the strict parser: no shared references, no prototype tricks, no lone surrogates.
    assertJsonValue(entry);
    r = c(parseJsonStrict(JSON.stringify(entry)));
  } catch (e) { return { valid: false, signatureValid: false, keyTrusted: false, reason: `verify error: ${e?.code ?? ''} ${e?.detail ?? e?.message ?? e}` }; }
  const signatureValid = r.signatureValid === true;
  const trusted = Array.isArray(opts.trustedKeys) ? opts.trustedKeys : null;
  const keyTrusted = signatureValid && !!trusted && typeof r.publicKeyB64 === 'string' && trusted.includes(r.publicKeyB64);
  let reason;
  if (!signatureValid) reason = `signature INVALID (${r.reason})`;
  else if (!trusted) reason = 'signature verifies over the bytes, but no trustedKeys supplied — authorship UNVERIFIED (a self-signed forgery reaches here)';
  else if (!keyTrusted) reason = 'signature verifies, but the signing key is NOT in the trusted set — untrusted key (likely forgery)';
  else reason = `authentic: ML-DSA-65 signature by a trusted key over the exact ${profile} bytes`;
  return { valid: signatureValid && keyTrusted, signatureValid, keyTrusted, reason };
}
