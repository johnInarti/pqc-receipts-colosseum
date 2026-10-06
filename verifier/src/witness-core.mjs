/**
 * Core witness-object construction + ML-DSA-65 sign/verify. Shared by both modes:
 *   - self-attest.mjs: the SELLER's own key signs. Proves the bytes weren't altered after the
 *     fact; proves NOTHING about who authored them (same caveat as any self-issued receipt —
 *     see profiles.mjs's TRUST MODEL note). Free, fully offline, zero network dependency.
 *   - notary.mjs: a FractalAI-controlled key signs, via a network call to a FractalAI-operated
 *     endpoint. This is the only mode that is an actual independent third-party attestation.
 *
 * Docs/README MUST NOT call self-attest output a "witness" or "notarized" receipt — that
 * language is reserved for notary-mode output, where the signer is provably not the seller.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import { jcs, utf8 } from './canon.mjs';

export const SCHEMA = 'fractalai.x402-settlement-seal/0.1';
export const SELF_ATTEST_DOMAIN = 'FRACTALAI-x402-self-attest-v1';
// Matches frontend/lib/x402-receipt-signer.ts's servedProofMessage('x402-witness', digestHex) exactly
// (X402_SERVED_PROOF_DOMAIN + '\n' + routeId) — the notary endpoint signs with that SAME, already
// production-audited keypair/domain-separation machinery, not a second one-off key.
export const NOTARY_DOMAIN = 'FRACTALAI-x402-served-v1\nx402-witness';

const sha256hex = (bufOrStr) => {
  const h = createHash('sha256');
  h.update(bufOrStr);
  return h.digest('hex');
};

/**
 * Build the unsigned settlement-seal body from an x402 SettleResultContext-shaped input.
 * Every field is derived from what the resource server ALREADY has at settle time — no new
 * data collection, no PII.
 *
 * @param {object} p
 * @param {string} [p.resource] - resource URL, if known (HTTPTransportContext.request.path or similar)
 * @param {object} p.requirements - the matched PaymentRequirements (network, asset, payTo, scheme)
 * @param {object} p.result - the SettleResponse (payer, transaction, amount, network, success)
 * @param {Buffer|Uint8Array|null} [p.responseBody] - the served response bytes, if available
 * @returns {object} unsigned seal body (no content_id, no signature yet)
 */
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

/** content_id = sha256(JCS(body)) — same redundant-integrity-anchor pattern as a2a-signed-receipts. */
export function contentId(body) {
  return sha256hex(jcs(body));
}

/**
 * Sign a seal body with an ML-DSA-65 secret key under the given domain separator.
 * @returns {{ algorithm: 'ml-dsa-65', domain: string, content_id: string, public_key: string, signature: string, body: object }}
 */
export function signSeal(body, { domain, secretKey, publicKey }) {
  const cid = contentId(body);
  const message = `${domain}\n${cid}`;
  const signature = ml_dsa65.sign(utf8(message), secretKey);
  return {
    algorithm: 'ml-dsa-65',
    domain,
    content_id: cid,
    public_key: Buffer.from(publicKey).toString('base64'),
    signature: Buffer.from(signature).toString('base64'),
    body,
  };
}

/**
 * Verify a signed seal. FAIL-CLOSED: returns { valid:false, reason } on ANY inconsistency
 * (recomputed content_id mismatch, bad signature, wrong domain) rather than throwing — a
 * verifier should never crash on a malformed/forged seal (the exact class of bug found and
 * fixed in CSOAI-ORG/a2a-signed-receipts#2 this session).
 *
 * @param {object} seal - { algorithm, domain, content_id, public_key, signature, body }
 * @param {{ expectedDomain?: string, trustedPublicKeysB64?: string[] }} [opts] -
 *   trustedPublicKeysB64, when given, gates `keyTrusted`; omit to check integrity/signature only.
 */
/** Derives which mode a seal CLAIMS to be from its own `domain` field — a caller who forgets to
 * pass `expectedDomain` still gets an explicit signal instead of silently treating a self-attest
 * seal (seller's own key) the same as a notary seal (FractalAI's key). This is a claim only —
 * `keyTrusted` (via trustedPublicKeysB64) is still the only thing that actually authenticates it. */
function modeFromDomain(domain) {
  if (domain === SELF_ATTEST_DOMAIN) return 'self-attest';
  if (domain === NOTARY_DOMAIN) return 'notary';
  return 'unknown';
}

export function verifySeal(seal, opts = {}) {
  try {
    if (!seal || typeof seal !== 'object') return { valid: false, keyTrusted: false, mode: 'unknown', reason: 'not an object' };
    const { algorithm, domain, content_id: cid, public_key, signature, body } = seal;
    const mode = modeFromDomain(domain);
    if (algorithm !== 'ml-dsa-65') return { valid: false, keyTrusted: false, mode, reason: `unsupported algorithm '${algorithm}'` };
    if (opts.expectedDomain && domain !== opts.expectedDomain) {
      return { valid: false, keyTrusted: false, mode, reason: `domain '${domain}' != expected '${opts.expectedDomain}'` };
    }
    if (!body || typeof body !== 'object') return { valid: false, keyTrusted: false, mode, reason: 'missing body' };
    const recomputed = contentId(body);
    if (recomputed !== cid) return { valid: false, keyTrusted: false, mode, reason: 'content_id mismatch — body was altered' };
    const pk = Buffer.from(public_key, 'base64');
    const sig = Buffer.from(signature, 'base64');
    const message = `${domain}\n${cid}`;
    const sigOk = ml_dsa65.verify(sig, utf8(message), pk) === true;
    if (!sigOk) return { valid: false, keyTrusted: false, mode, reason: 'signature does not verify' };
    let keyTrusted = null; // null = not evaluated (no trustedPublicKeysB64 given)
    if (opts.trustedPublicKeysB64) {
      keyTrusted = opts.trustedPublicKeysB64.includes(public_key);
    }
    return { valid: keyTrusted !== false, keyTrusted, mode, reason: keyTrusted === false ? 'signature valid but key not trusted' : 'ok' };
  } catch (e) {
    return { valid: false, keyTrusted: false, mode: 'unknown', reason: `${e.constructor.name}: ${e.message}` };
  }
}
