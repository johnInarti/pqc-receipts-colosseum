/**
 * Seal construction (issuer side) + a compatibility `verifySeal` that DELEGATES every trust decision to
 * Trust Kernel v2 (spec/TRUST-KERNEL.md). Nothing in this file decides trust on its own anymore.
 *   - self-attest: the SELLER's own key signs. Proves the bytes were not altered; proves nothing about who
 *     authored them. The FractalAI directory never authorizes it; only an explicit pinned key set can.
 *   - notary (x402-witness): a FractalAI receipt key signs; trusted only through the pinned directory roots
 *     (or an explicit pinned key set, reported as an override).
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { verifySync, jcsSigned, sha256hex, utf8, assertJsonValue, SEAL_SCHEMA, SELF_ATTEST_DOMAIN, KINDS } from '@fractalai/pqc-trust-kernel';

export const SCHEMA = SEAL_SCHEMA;
export { SELF_ATTEST_DOMAIN };
export const NOTARY_DOMAIN = KINDS['x402-seal'].domain;

/** Build the unsigned settlement-seal body from an x402 SettleResultContext-shaped input (no PII). */
export function buildSealBody({ resource, requirements, result, responseBody }) {
  return {
    schema: SCHEMA,
    resource: resource ?? null,
    scheme: requirements?.scheme ?? null,
    network: result?.network ?? requirements?.network ?? null,
    asset: requirements?.asset ?? null,
    payTo: requirements?.payTo ?? null,
    amount: result?.amount ?? requirements?.amount ?? null,
    payer: result?.payer ?? null,
    transaction: result?.transaction ?? null,
    success: result?.success ?? null,
    response_sha256: responseBody != null ? sha256hex(responseBody) : null,
    sealed_at: new Date().toISOString(),
  };
}

/** content_id = sha256(JCS(body)) over the SIGNED-JSON subset (safe integers only; see spec §4.3). */
export function contentId(body) {
  return sha256hex(jcsSigned(body));
}

/** Sign a seal body. Refuses bodies outside the signed-JSON subset (they could never verify). */
export function signSeal(body, { domain, secretKey, publicKey }) {
  if (domain !== NOTARY_DOMAIN && domain !== SELF_ATTEST_DOMAIN) throw new Error('signSeal: domain must be the notary or the self-attest seal domain');
  const cid = contentId(body);
  const signature = ml_dsa65.sign(utf8(`${domain}\n${cid}`), secretKey);
  return {
    algorithm: 'ml-dsa-65', domain, content_id: cid,
    public_key: Buffer.from(publicKey).toString('base64'), signature: Buffer.from(signature).toString('base64'), body,
  };
}

/**
 * Compatibility wrapper (synchronous, offline). Returns the legacy shape plus the full kernel `verdict`.
 * `valid` now means exactly the kernel's `valid` (authentic AND trusted). Without a trust source the result
 * is valid:false, keyTrusted:null — a self-signed seal never gets a green check.
 * @param {object} seal
 * @param {{ expectedDomain?: string, trustedPublicKeysB64?: string[], directory?: object|string, now?: number }} [opts]
 */
export function verifySeal(seal, opts = {}) {
  const kinds = opts.expectedDomain === SELF_ATTEST_DOMAIN ? ['self-attest-seal'] : opts.expectedDomain === NOTARY_DOMAIN ? ['x402-seal'] : opts.expectedDomain !== undefined ? [] : ['x402-seal', 'self-attest-seal'];
  if (kinds.length === 0) return { valid: false, keyTrusted: false, mode: 'unknown', reason: 'expectedDomain is not a seal domain', verdict: null };
  let input;
  try { assertJsonValue(seal); input = JSON.stringify(seal); } catch (e) { return { valid: false, keyTrusted: false, mode: 'unknown', reason: `${e?.code ?? 'INPUT_SHAPE'}: ${e?.detail ?? 'not a JSON value'}`, verdict: null }; }
  const k = { kinds, now: opts.now };
  if (opts.trustedPublicKeysB64) k.trustedKeys = JSON.stringify(opts.trustedPublicKeysB64);
  if (opts.directory) k.directory = typeof opts.directory === 'string' ? opts.directory : JSON.stringify(opts.directory);
  const v = verifySync(input ?? 'null', k);
  const mode = v.kind === 'x402-seal' ? 'notary' : v.kind === 'self-attest-seal' ? 'self-attest' : 'unknown';
  const noTrustSource = !opts.trustedPublicKeysB64 && !opts.directory;
  const keyTrusted = !v.levels.authentic ? false : noTrustSource ? null : v.levels.trusted;
  const reason = v.valid ? 'ok' : v.reasons.length ? `${v.reasons[0].code}: ${v.reasons[0].detail}` : 'not valid';
  return { valid: v.valid, keyTrusted, mode, signatureValid: v.levels.authentic, reason, verdict: v };
}
