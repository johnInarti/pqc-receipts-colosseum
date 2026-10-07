/**
 * JSON-RPC over boundedFetch (hard deadline, byte cap, strict JSON). One call → one URL; the anchor
 * verifiers run their whole check independently against every configured URL and require the resulting
 * FACTS to agree (spec §7.4), so a single lying RPC cannot pass and a disagreement fails closed.
 */
import { C, KernelError } from './codes.mjs';
import { boundedFetch, parseJsonStrict, isPlainObject, oneLine } from './hygiene.mjs';

let seq = 0;
export async function rpcCall(url, method, params, { fetchImpl, timeoutMs = 20_000, maxBytes = 4 * 1024 * 1024 } = {}) {
  const id = ++seq;
  const text = await boundedFetch(url, {
    method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }), timeoutMs, maxBytes, fetchImpl,
  });
  let j;
  try { j = parseJsonStrict(text, { MAX_JSON_BYTES: maxBytes }); } catch (e) { throw new KernelError(C.RPC_ERROR, `${method}: unparsable response (${e.code ?? 'JSON'})`); }
  if (!isPlainObject(j)) throw new KernelError(C.RPC_ERROR, `${method}: response is not an object`);
  if (j.error !== undefined && j.error !== null) throw new KernelError(C.RPC_ERROR, `${method}: ${oneLine(j.error?.message ?? JSON.stringify(j.error), 160)}`);
  if (!Object.prototype.hasOwnProperty.call(j, 'result')) throw new KernelError(C.RPC_ERROR, `${method}: no result`);
  return j.result;
}

/** Stable comparison of fact objects produced by different RPCs. */
export function sameFacts(a, b, fields) {
  return fields.every((f) => JSON.stringify(a[f]) === JSON.stringify(b[f]));
}
