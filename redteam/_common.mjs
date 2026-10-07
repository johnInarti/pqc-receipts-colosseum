import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
export { ml_dsa65 };
export const b64 = (u) => Buffer.from(u).toString('base64');
export const utf8 = (s) => new TextEncoder().encode(s);
// Same deterministic ISSUER seed the public golden vectors use (conformance/src/gen-vectors.mjs) — test-only key.
export const issuer = ml_dsa65.keygen(new Uint8Array(32).map((_, i) => (i * 5 + 1) & 0xff));
export const keyFromByte = (b) => ml_dsa65.keygen(new Uint8Array(32).fill(b));
export const verdict = (vulnerable, msg) => { console.log((vulnerable ? 'VULNERABLE: ' : 'OK (not vulnerable): ') + msg); return vulnerable; };
