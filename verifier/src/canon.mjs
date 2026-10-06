/**
 * RFC 8785-style JSON canonicalisation (sorted keys, no whitespace, UTF-8) — the exact scheme
 * used across every FractalAI x402/receipt signing surface (see profiles.mjs's `jcs`, and the
 * a2a-signed-receipts interceptor.py `_canon`), so a witnessed object hashes identically
 * everywhere it's checked.
 *
 * Depth- and node-count-limited (red-team-supremo, 2026-09-05): the sibling frontend copy
 * (frontend/lib/x402-witness-canon.ts) got a MAX_DEPTH guard against unbounded-recursion DoS
 * back on 2026-09-05, but THIS published copy — the one `npm install
 * @fractalai/x402-pqc-witness` actually ships, and what `contentId`/`signSeal` call into — never
 * received it, contradicting that day's own commit message ("depth-limited (24),
 * boundary-tested"). Fixed here, plus a MAX_NODES cap the frontend copy didn't have either: depth
 * alone doesn't bound a WIDE object (many sibling keys at one level).
 */
const MAX_DEPTH = 24;
const MAX_NODES = 10_000;

export function jcs(v, depth = 0, counter = { n: 0 }) {
  if (++counter.n > MAX_NODES) throw new Error(`jcs: too many nodes (>${MAX_NODES}) — refusing to canonicalise`);
  if (depth > MAX_DEPTH) throw new Error(`jcs: nesting depth exceeds ${MAX_DEPTH} — refusing to canonicalise`);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('jcs: non-finite number (NaN/Infinity forbidden)');
    return JSON.stringify(v);
  }
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map((x) => jcs(x, depth + 1, counter)).join(',') + ']';
  if (typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k], depth + 1, counter)).join(',') + '}';
  }
  throw new Error(`jcs: unsupported ${typeof v}`);
}

export const utf8 = (s) => new TextEncoder().encode(s);
