/**
 * Replay / record transports for the corpus (format: corpus/README.md §3).
 * A transcript is a list of { url, method, params, result } (or { …, error }). Replay matches a JSON-RPC
 * request on (url, method, JCS(params)); an unmatched call answers a JSON-RPC error (fail closed).
 * Language-neutral: the Python runner implements the same matching.
 */
import { jcs, parseJsonStrict } from '../../kernel/src/index.mjs';

const key = (url, method, params) => `${url}\u0000${method}\u0000${jcs(params ?? [])}`;
const respond = (obj) => ({ ok: true, status: 200, headers: { get: (h) => (h.toLowerCase() === 'content-type' ? 'application/json' : null) }, text: async () => JSON.stringify(obj) });

export function replayFetch(transcript) {
  const map = new Map();
  for (const t of transcript || []) map.set(key(t.url, t.method, t.params), t);
  const fetchImpl = async (url, init) => {
    const req = parseJsonStrict(init.body);
    const hit = map.get(key(url, req.method, req.params));
    if (!hit) return respond({ jsonrpc: '2.0', id: req.id, error: { code: -32601, message: `not in transcript: ${req.method}` } });
    return respond(hit.error !== undefined ? { jsonrpc: '2.0', id: req.id, error: hit.error } : { jsonrpc: '2.0', id: req.id, result: hit.result });
  };
  return fetchImpl;
}

/** Wrap a real fetch; returns { fetchImpl, transcript } with urls rewritten through `label(url)`. */
export function recordingFetch(label = (u) => u, realFetch = globalThis.fetch) {
  const transcript = [];
  const fetchImpl = async (url, init) => {
    const res = await realFetch(url, init);
    const text = await res.text();
    const req = parseJsonStrict(init.body);
    const body = parseJsonStrict(text);
    transcript.push(body.error !== undefined && body.error !== null
      ? { url: label(url), method: req.method, params: req.params, error: body.error }
      : { url: label(url), method: req.method, params: req.params, result: body.result });
    return { ok: res.ok, status: res.status, headers: res.headers, text: async () => text };
  };
  return { fetchImpl, transcript };
}
