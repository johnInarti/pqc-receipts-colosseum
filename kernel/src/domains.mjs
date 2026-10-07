/**
 * Normative domain table (spec/TRUST-KERNEL.md §5). The signed message of every receipt kind is
 * RECONSTRUCTED by the kernel from the kind's fixed domain and the signed content — a `domain`,
 * `served_domain` or `signed_message` field carried by the receipt is never used to build the message,
 * only compared byte-for-byte with the reconstruction. A key authorizes a kind only if its directory
 * `use` is listed for that kind.
 */
export const SERVED_PREFIX = 'FRACTALAI-x402-served-v1';
export const KEY_DIR_DOMAIN = 'FRACTALAI-key-directory-v1';
export const SELF_ATTEST_DOMAIN = 'FRACTALAI-x402-self-attest-v1';
export const MIDAS_CANON_HEADER = 'FRACTALAI-midas-alert-v1';
export const SEAL_SCHEMA = 'fractalai.x402-settlement-seal/0.1';

export const USE = Object.freeze({ RECEIPT: 'x402-receipt', GOVERNANCE: 'key-directory-governance' });

/** route ids with a dedicated kind — they can never be presented as a generic served proof. */
export const RESERVED_ROUTES = Object.freeze({
  'midas-alert': 'midas-alert',
  'x402-witness': 'x402-seal',
  'x402-attest-decision': 'acp-verdict',
});
export const ROUTE_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

export const KINDS = Object.freeze({
  'midas-alert': {
    domain: `${SERVED_PREFIX}\nmidas-alert`,
    message: (id) => `${SERVED_PREFIX}\nmidas-alert\n${id}`,
    uses: [USE.RECEIPT], trust: 'directory', signed_time: 'canonical.emitted_at', anchorable: true,
  },
  'x402-seal': {
    domain: `${SERVED_PREFIX}\nx402-witness`,
    message: (cid) => `${SERVED_PREFIX}\nx402-witness\n${cid}`,
    uses: [USE.RECEIPT], trust: 'directory', signed_time: 'body.sealed_at', anchorable: true,
  },
  'acp-verdict': {
    domain: `${SERVED_PREFIX}\nx402-attest-decision`,
    message: (d) => `${SERVED_PREFIX}\nx402-attest-decision\n${d}`,
    uses: [USE.RECEIPT], trust: 'directory', signed_time: null, anchorable: false,
  },
  'served-proof': {
    domain: SERVED_PREFIX,
    message: (route, digest) => `${SERVED_PREFIX}\n${route}\n${digest}`,
    uses: [USE.RECEIPT], trust: 'directory', signed_time: null, anchorable: false,
  },
  'self-attest-seal': {
    domain: SELF_ATTEST_DOMAIN,
    message: (cid) => `${SELF_ATTEST_DOMAIN}\n${cid}`,
    // A seller's own key: FractalAI's directory never authorizes it. Trust only via an explicit pinned key set.
    uses: [], trust: 'pinned-set-only', signed_time: 'body.sealed_at', anchorable: true,
  },
});
export const KIND_NAMES = Object.freeze(Object.keys(KINDS));
