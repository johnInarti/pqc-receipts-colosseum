/**
 * Shared input/output hygiene (spec/TRUST-KERNEL.md \u00a78). Every byte that reaches the decision layer
 * passes through here: strict JSON (duplicate keys and lone surrogates are REJECTED, not resolved),
 * hard size/depth/node limits, canonical base64/hex, a fetch with ONE deadline covering headers+body and
 * a streamed byte cap, and an output escaper for terminals / CI logs.
 */
import { C, KernelError, fail } from './codes.mjs';

export const LIMITS = Object.freeze({
  MAX_JSON_BYTES: 2 * 1024 * 1024,
  MAX_DEPTH: 32,
  MAX_NODES: 100_000,
  MAX_STRING: 1024 * 1024,
  FETCH_TIMEOUT_MS: 20_000,
  FETCH_MAX_BYTES: 2 * 1024 * 1024,
});

const isHighSur = (c) => c >= 0xd800 && c <= 0xdbff;
const isLowSur = (c) => c >= 0xdc00 && c <= 0xdfff;

/**
 * RFC 8259 JSON parser that refuses everything a lenient parser would silently "resolve":
 * duplicate object keys (JSON.parse keeps the last, other stacks the first → parser differential),
 * lone UTF-16 surrogates (not representable in UTF-8 → canonicalisation differential), a leading BOM,
 * trailing garbage, and inputs beyond the size/depth/node limits. Objects are created with a null
 * prototype, so `__proto__` is an ordinary key and cannot pollute anything.
 * @param {string|Uint8Array} input
 */
export function parseJsonStrict(input, limits = {}) {
  const L = { ...LIMITS, ...limits };
  let text;
  if (typeof input === 'string') text = input;
  else if (input instanceof Uint8Array) {
    if (input.length > L.MAX_JSON_BYTES) fail(C.JSON_TOO_LARGE, `input is ${input.length} bytes (> ${L.MAX_JSON_BYTES})`);
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(input); } catch { fail(C.JSON_INVALID, 'input is not valid UTF-8'); }
  } else fail(C.JSON_INVALID, 'input is not text');
  // UTF-8 length bound (cheap upper bound first, exact second)
  if (text.length > L.MAX_JSON_BYTES || new TextEncoder().encode(text).length > L.MAX_JSON_BYTES) fail(C.JSON_TOO_LARGE, `input exceeds ${L.MAX_JSON_BYTES} bytes`);
  if (text.charCodeAt(0) === 0xfeff) fail(C.JSON_INVALID, 'byte-order mark not allowed');
  let i = 0, nodes = 0;
  const n = text.length;
  const err = (m) => fail(C.JSON_INVALID, `${m} at offset ${i}`);
  const ws = () => { while (i < n) { const c = text.charCodeAt(i); if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) i++; else break; } };
  const str = () => {
    i++; // opening quote
    let out = '';
    let start = i;
    for (;;) {
      if (i >= n) err('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) { out += text.slice(start, i); i++; break; }
      if (c < 0x20) err('control character in string');
      if (isHighSur(c)) {
        const d = text.charCodeAt(i + 1);
        if (!isLowSur(d)) fail(C.JSON_LONE_SURROGATE, `lone high surrogate at offset ${i}`);
        i += 2; continue;
      }
      if (isLowSur(c)) fail(C.JSON_LONE_SURROGATE, `lone low surrogate at offset ${i}`);
      if (c === 0x5c) {
        out += text.slice(start, i);
        const e = text[i + 1];
        i += 2;
        if (e === '"') out += '"'; else if (e === '\\') out += '\\'; else if (e === '/') out += '/';
        else if (e === 'b') out += '\b'; else if (e === 'f') out += '\f'; else if (e === 'n') out += '\n';
        else if (e === 'r') out += '\r'; else if (e === 't') out += '\t';
        else if (e === 'u') {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) err('bad \\u escape');
          const cu = parseInt(hex, 16); i += 4;
          if (isHighSur(cu)) {
            const hex2 = text.slice(i, i + 6);
            if (!/^\\u[0-9a-fA-F]{4}$/.test(hex2) || !isLowSur(parseInt(hex2.slice(2), 16))) fail(C.JSON_LONE_SURROGATE, `lone high surrogate escape at offset ${i - 6}`);
            out += String.fromCharCode(cu, parseInt(hex2.slice(2), 16)); i += 6;
          } else if (isLowSur(cu)) fail(C.JSON_LONE_SURROGATE, `lone low surrogate escape at offset ${i - 6}`);
          else out += String.fromCharCode(cu);
        } else err('bad escape');
        start = i;
        if (out.length > L.MAX_STRING) fail(C.JSON_TOO_LARGE, 'string too long');
        continue;
      }
      i++;
    }
    if (out.length > L.MAX_STRING) fail(C.JSON_TOO_LARGE, 'string too long');
    return out;
  };
  const num = () => {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 400));
    if (!m) err('bad number');
    i += m[0].length;
    const v = Number(m[0]);
    if (!Number.isFinite(v)) err('number out of range');
    return v;
  };
  const value = (depth) => {
    if (depth > L.MAX_DEPTH) fail(C.JSON_TOO_DEEP, `nesting depth exceeds ${L.MAX_DEPTH}`);
    if (++nodes > L.MAX_NODES) fail(C.JSON_TOO_LARGE, `more than ${L.MAX_NODES} JSON nodes`);
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const obj = Object.create(null); ws();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        ws(); if (text[i] !== '"') err('expected object key');
        const k = str();
        if (Object.prototype.hasOwnProperty.call(obj, k)) fail(C.JSON_DUPLICATE_KEY, `duplicate key ${JSON.stringify(k).slice(0, 80)}`);
        ws(); if (text[i] !== ':') err('expected :'); i++;
        obj[k] = value(depth + 1);
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return obj; }
        err('expected , or }');
      }
    }
    if (c === '[') {
      i++; const arr = []; ws();
      if (text[i] === ']') { i++; return arr; }
      for (;;) {
        arr.push(value(depth + 1)); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return arr; }
        err('expected , or ]');
      }
    }
    if (c === '"') return str();
    if (c === '-' || (c >= '0' && c <= '9')) return num();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    return err('unexpected token');
  };
  const v = value(0);
  ws();
  if (i !== n) err('trailing characters');
  return v;
}

/** Deep check that an already-parsed value respects the same limits (for callers passing objects). */
export function assertJsonValue(v, limits = {}) {
  const L = { ...LIMITS, ...limits };
  let nodes = 0;
  const walk = (x, d) => {
    if (d > L.MAX_DEPTH) fail(C.JSON_TOO_DEEP, `nesting depth exceeds ${L.MAX_DEPTH}`);
    if (++nodes > L.MAX_NODES) fail(C.JSON_TOO_LARGE, `more than ${L.MAX_NODES} JSON nodes`);
    if (x === null || typeof x === 'boolean') return;
    if (typeof x === 'number') { if (!Number.isFinite(x)) fail(C.INPUT_SHAPE, 'non-finite number'); return; }
    if (typeof x === 'string') {
      if (x.length > L.MAX_STRING) fail(C.JSON_TOO_LARGE, 'string too long');
      for (let k = 0; k < x.length; k++) {
        const c = x.charCodeAt(k);
        if (isHighSur(c)) { if (!isLowSur(x.charCodeAt(k + 1))) fail(C.JSON_LONE_SURROGATE, 'lone surrogate in string'); k++; }
        else if (isLowSur(c)) fail(C.JSON_LONE_SURROGATE, 'lone surrogate in string');
      }
      return;
    }
    if (Array.isArray(x)) { for (const y of x) walk(y, d + 1); return; }
    if (typeof x === 'object') {
      const proto = Object.getPrototypeOf(x);
      if (proto !== null && proto !== Object.prototype) fail(C.INPUT_SHAPE, 'non-plain object');
      for (const k of Object.keys(x)) { walk(k, d + 1); walk(x[k], d + 1); }
      return;
    }
    fail(C.INPUT_SHAPE, `unsupported JSON type ${typeof x}`);
  };
  walk(v, 0);
  return v;
}

export const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export const own = (o, k) => isPlainObject(o) && Object.prototype.hasOwnProperty.call(o, k);

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const B64_DEC = (() => { const t = new Int16Array(128).fill(-1); const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; for (let k = 0; k < 64; k++) t[a.charCodeAt(k)] = k; return t; })();
const B64_ENC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function b64encode(bytes) {
  let s = '';
  let k = 0;
  for (; k + 2 < bytes.length; k += 3) { const v = (bytes[k] << 16) | (bytes[k + 1] << 8) | bytes[k + 2]; s += B64_ENC[v >> 18] + B64_ENC[(v >> 12) & 63] + B64_ENC[(v >> 6) & 63] + B64_ENC[v & 63]; }
  if (k < bytes.length) {
    const rem = bytes.length - k;
    const v = (bytes[k] << 16) | ((rem > 1 ? bytes[k + 1] : 0) << 8);
    s += B64_ENC[v >> 18] + B64_ENC[(v >> 12) & 63] + (rem > 1 ? B64_ENC[(v >> 6) & 63] : '=') + '=';
  }
  return s;
}

/** Canonical RFC 4648 \u00a74 base64 only: padded, standard alphabet, no whitespace, zero padding bits
 * (decode→encode must round-trip, so one byte string has exactly one accepted text form). */
export function b64decodeStrict(s, expectedLen, what = 'value') {
  if (typeof s !== 'string' || s.length === 0 || !B64_RE.test(s)) fail(C.B64_NONCANONICAL, `${what} is not canonical base64`);
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((s.length / 4) * 3 - pad);
  let o = 0;
  for (let k = 0; k < s.length; k += 4) {
    const a = B64_DEC[s.charCodeAt(k)], b = B64_DEC[s.charCodeAt(k + 1)];
    const c = s[k + 2] === '=' ? 0 : B64_DEC[s.charCodeAt(k + 2)], d = s[k + 3] === '=' ? 0 : B64_DEC[s.charCodeAt(k + 3)];
    const v = (a << 18) | (b << 12) | (c << 6) | d;
    if (o < out.length) out[o++] = v >> 16;
    if (o < out.length) out[o++] = (v >> 8) & 255;
    if (o < out.length) out[o++] = v & 255;
  }
  if (b64encode(out) !== s) fail(C.B64_NONCANONICAL, `${what} has non-zero padding bits`);
  if (expectedLen !== undefined && out.length !== expectedLen) {
    fail(expectedLen === 1952 ? C.KEY_SIZE : expectedLen === 3309 ? C.SIG_SIZE : C.INPUT_SHAPE, `${what} is ${out.length} bytes, expected ${expectedLen}`);
  }
  return out;
}

export const isHex = (s, len) => typeof s === 'string' && (len === undefined ? /^[0-9a-f]+$/ : new RegExp(`^[0-9a-f]{${len}}$`)).test(s);
export const isHex0x = (s, len) => typeof s === 'string' && new RegExp(`^0x[0-9a-fA-F]{${len}}$`).test(s);
export const isSafeUint = (v) => Number.isSafeInteger(v) && v >= 0;
export function hexToBytes(h) {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  if (s.length % 2 || !/^[0-9a-fA-F]*$/.test(s)) fail(C.INPUT_SHAPE, 'bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let k = 0; k < out.length; k++) out[k] = parseInt(s.slice(2 * k, 2 * k + 2), 16);
  return out;
}
export const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
/** JSON-RPC quantity: 0x-prefixed hex without leading zeros (we accept leading zeros, but nothing else). */
export function qty(h, what = 'quantity') {
  if (typeof h !== 'string' || !/^0x[0-9a-fA-F]{1,16}$/.test(h)) fail(C.ANCHOR_LOG_MALFORMED, `${what} is not a hex quantity`);
  const v = Number.parseInt(h.slice(2), 16);
  if (!Number.isSafeInteger(v)) fail(C.ANCHOR_LOG_MALFORMED, `${what} out of range`);
  return v;
}
export const toQty = (n) => '0x' + n.toString(16);

/**
 * Output escaping: one value → one line, no control/bidi/line-separator characters, bounded length.
 * Untrusted text (receipt fields, RPC error strings, URLs) MUST go through this before reaching a
 * terminal, a CI log (workflow-command injection) or a Markdown summary.
 */
export function oneLine(s, max = 600) {
  const t = String(s).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return t.length > max ? `${t.slice(0, max)}…(truncated)` : t;
}
/** JSON for a terminal: JSON.stringify already escapes C0 controls; additionally escape C1/bidi/separators. */
export function safeJson(v, space = 2) {
  return JSON.stringify(v, null, space).replace(/[\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/**
 * fetch with ONE hard deadline covering connection, headers AND body (a strongly referenced timer, not
 * AbortSignal.timeout, which can be collected after the headers arrive), a streamed byte cap (checked
 * while reading, not after buffering), no redirects, and https-only (http allowed for loopback only).
 * Returns the body as text. Never retries: callers decide (a retry can never turn into "valid").
 */
export async function boundedFetch(url, { method = 'GET', headers = {}, body, timeoutMs = LIMITS.FETCH_TIMEOUT_MS, maxBytes = LIMITS.FETCH_MAX_BYTES, fetchImpl = globalThis.fetch, allowInsecureLoopback = true } = {}) {
  let u;
  try { u = new URL(url); } catch { throw new KernelError(C.RPC_ERROR, `invalid URL ${oneLine(url, 120)}`); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  const custom = fetchImpl !== globalThis.fetch;
  if (!custom && u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback && allowInsecureLoopback)) {
    throw new KernelError(C.RPC_ERROR, `refusing non-HTTPS URL ${oneLine(url, 120)}`);
  }
  const ctl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ctl.abort(new Error(`deadline ${timeoutMs} ms`)); }, timeoutMs);
  try {
    const res = await fetchImpl(url, { method, headers, body, signal: ctl.signal, redirect: 'error' });
    if (!res || typeof res !== 'object') throw new KernelError(C.RPC_ERROR, 'no response');
    if (!res.ok) { try { await res.body?.cancel?.(); } catch { /* ignore */ } throw new KernelError(C.RPC_ERROR, `HTTP ${res.status} from ${oneLine(u.origin, 120)}`); }
    const len = Number(res.headers?.get?.('content-length'));
    if (Number.isFinite(len) && len > maxBytes) throw new KernelError(C.JSON_TOO_LARGE, `response larger than ${maxBytes} bytes`);
    // Mocks / replay transports may only implement text() or json(); real fetch exposes a stream.
    if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
      const chunks = []; let total = 0;
      for await (const ch of res.body) {
        total += ch.byteLength;
        if (total > maxBytes) { ctl.abort(); throw new KernelError(C.JSON_TOO_LARGE, `response larger than ${maxBytes} bytes`); }
        chunks.push(ch);
      }
      const all = new Uint8Array(total); let o = 0; for (const ch of chunks) { all.set(ch, o); o += ch.byteLength; }
      return new TextDecoder('utf-8', { fatal: false }).decode(all);
    }
    if (typeof res.text === 'function') {
      const t = await res.text();
      if (t.length > maxBytes) throw new KernelError(C.JSON_TOO_LARGE, `response larger than ${maxBytes} bytes`);
      return t;
    }
    if (typeof res.json === 'function') return JSON.stringify(await res.json());
    throw new KernelError(C.RPC_ERROR, 'response has no body');
  } catch (e) {
    if (e instanceof KernelError) throw e;
    if (timedOut) throw new KernelError(C.RPC_ERROR, `timeout after ${timeoutMs} ms (${oneLine(u.origin, 120)})`);
    throw new KernelError(C.RPC_ERROR, `fetch ${oneLine(u.origin, 120)} failed: ${oneLine(e?.message ?? e, 200)}`);
  } finally {
    clearTimeout(timer);
  }
}

/** GET a JSON document strictly (bounded fetch + strict parse). */
export async function fetchJsonStrict(url, opts = {}) {
  return parseJsonStrict(await boundedFetch(url, { ...opts, headers: { accept: 'application/json', ...(opts.headers || {}) } }));
}
