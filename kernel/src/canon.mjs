/**
 * RFC 8785 (JCS) canonicalisation. In ECMAScript this is exact: Number→string is ES Number::toString and
 * key order is UTF-16 code-unit order (Array.prototype.sort default). Other implementations (Python) MUST
 * reproduce both, or restrict themselves to the "signed JSON" subset below.
 *
 * SIGNED JSON SUBSET (spec §4.3): content that is hashed under a FractalAI domain (seal bodies, ACP
 * decisions) may contain only strings, booleans, null, arrays, objects and SAFE INTEGERS. Fractions,
 * exponents beyond 2^53 and lone surrogates are where language runtimes disagree, so they are refused
 * instead of canonicalised (`jcsSigned`). `jcs` (unrestricted) is kept for third-party profiles.
 */
import { C, fail } from './codes.mjs';

const MAX_DEPTH = 32;
const MAX_NODES = 100_000;

function walk(v, depth, counter, signed) {
  if (++counter.n > MAX_NODES) fail(C.JSON_TOO_LARGE, `jcs: more than ${MAX_NODES} nodes`);
  if (depth > MAX_DEPTH) fail(C.JSON_TOO_DEEP, `jcs: nesting depth exceeds ${MAX_DEPTH}`);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) fail(C.INPUT_SHAPE, 'jcs: non-finite number');
    if (signed && !Number.isSafeInteger(v)) fail(C.SIGNED_JSON_NUMBER, `signed JSON may only contain safe integers (got ${v})`);
    return JSON.stringify(Object.is(v, -0) ? 0 : v);
  }
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') {
    for (let k = 0; k < v.length; k++) {
      const c = v.charCodeAt(k);
      if (c >= 0xd800 && c <= 0xdbff) { const d = v.charCodeAt(k + 1); if (!(d >= 0xdc00 && d <= 0xdfff)) fail(C.JSON_LONE_SURROGATE, 'jcs: lone surrogate'); k++; }
      else if (c >= 0xdc00 && c <= 0xdfff) fail(C.JSON_LONE_SURROGATE, 'jcs: lone surrogate');
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map((x) => walk(x, depth + 1, counter, signed)).join(',') + ']';
  if (typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => walk(k, depth + 1, counter, signed) + ':' + walk(v[k], depth + 1, counter, signed)).join(',') + '}';
  }
  return fail(C.INPUT_SHAPE, `jcs: unsupported ${typeof v}`);
}

export const jcs = (v) => walk(v, 0, { n: 0 }, false);
export const jcsSigned = (v) => walk(v, 0, { n: 0 }, true);
export const utf8 = (s) => new TextEncoder().encode(s);
