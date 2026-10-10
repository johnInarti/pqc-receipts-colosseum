// Locating the FractalAI key directory (FRACTALAI-key-directory-v1) when /.well-known/x402-receipt-keys
// carries the x402 delivery-receipt format instead.
//
// Why: the x402 delivery-receipt spec (§7.1) reserves `<issuer>/.well-known/x402-receipt-keys` for its own
// directory format (`x402-receipt-key-directory/1`). FractalAI's chain of epochs 1..n predates that format
// and lived at the same path. It moves, byte for byte, to LEGACY_DIRECTORY_PATH. Receipts already signed
// embed the old URL in their signed bytes and can never be changed, so a verifier that is handed that URL
// must still find the chain: this resolver fetches the URL and, if what it gets is not a
// FRACTALAI-key-directory-v1 document, fetches the legacy path ON THE SAME ORIGIN and requires that one to
// be. It never follows a document's own pointer (a forged directory cannot redirect the verifier), and
// it never accepts the spec-format document as a FractalAI epoch.
import { boundedFetch, parseJsonStrict } from './hygiene.mjs';
import { C, KernelError } from './codes.mjs';

export const LEGACY_DIRECTORY_SPEC = 'FRACTALAI-key-directory-v1';
export const LEGACY_DIRECTORY_PATH = '/.well-known/fractalai-key-directory';
export const SPEC_DIRECTORY_PATH = '/.well-known/x402-receipt-keys';

const specOf = (text) => {
  try { const d = parseJsonStrict(text); return d && typeof d === 'object' && !Array.isArray(d) ? d.spec : undefined; }
  catch { return undefined; }
};

/**
 * Fetch the FractalAI key directory text starting from `url`.
 * @param {string} url            a directory URL (legacy or spec path) on the issuer's origin
 * @param {object} [opts]         passed to boundedFetch (fetchImpl, timeoutMs, ...)
 * @returns {Promise<{ text: string, url: string, relocated: boolean }>}
 */
export async function fetchLegacyDirectory(url, opts = {}) {
  const get = (u) => boundedFetch(u, { headers: { accept: 'application/json' }, ...opts });
  let first;
  try { first = await get(url); } catch (e) { first = e; }
  if (typeof first === 'string' && specOf(first) === LEGACY_DIRECTORY_SPEC) return { text: first, url, relocated: false };
  const alt = new URL(LEGACY_DIRECTORY_PATH, url).href;
  if (alt === url) {
    if (first instanceof Error) throw first;
    throw new KernelError(C.DIRECTORY_INVALID, `${url} is not a ${LEGACY_DIRECTORY_SPEC} document`);
  }
  const text = await get(alt);
  if (specOf(text) !== LEGACY_DIRECTORY_SPEC) {
    throw new KernelError(C.DIRECTORY_INVALID, `neither ${url} nor ${alt} is a ${LEGACY_DIRECTORY_SPEC} document`);
  }
  return { text, url: alt, relocated: true };
}
