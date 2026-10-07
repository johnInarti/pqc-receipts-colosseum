/**
 * Solana wire format, base58 and the canonical anchor memo — pure, bounds-checked (spec §7.3).
 * Shared by the verifier (parse) and the issuer tooling (build). No Solana SDK.
 */
import { C, fail } from '../codes.mjs';

export const ANCHOR_SCHEME = 'fractalai.pqc-receipt-anchor/1';
export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function b58encode(bytes) {
  const b = Uint8Array.from(bytes);
  let n = 0n;
  for (const x of b) n = n * 256n + BigInt(x);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x !== 0) break; s = '1' + s; }
  return s;
}
export function b58decode(str, expectedLen) {
  if (typeof str !== 'string' || str.length === 0 || str.length > 128 || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(str)) fail(C.INPUT_SHAPE, 'invalid base58');
  let n = 0n;
  for (const c of str) n = n * 58n + BigInt(B58.indexOf(c));
  const out = [];
  while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of str) { if (c !== '1') break; out.unshift(0); }
  const r = Uint8Array.from(out);
  if (expectedLen !== undefined && r.length !== expectedLen) fail(C.INPUT_SHAPE, `base58 value is ${r.length} bytes, expected ${expectedLen}`);
  if (b58encode(r) !== str) fail(C.INPUT_SHAPE, 'non-canonical base58');
  return r;
}

/** The ONLY accepted memo: `scheme|rid=<64hex>|ph=<64hex>|kid=<16hex>|obs=<decimal>` (lowercase, no 0x). */
export const buildMemo = ({ receipt_id, payload_hash, kid16, observed_at }) =>
  `${ANCHOR_SCHEME}|rid=${receipt_id}|ph=${payload_hash}|kid=${kid16}|obs=${observed_at}`;

export function shortvec(n) {
  const out = [];
  for (;;) { const b = n & 0x7f; n >>= 7; if (n === 0) { out.push(b); return out; } out.push(b | 0x80); }
}

/** Parse a legacy or v0 transaction. Every read is bounds-checked; trailing bytes, out-of-range indexes,
 * non-minimal shortvecs and unsupported versions throw SOL_TX_MALFORMED. */
export function parseTransaction(wire) {
  const buf = Uint8Array.from(wire);
  let i = 0;
  const bad = (m) => fail(C.SOL_TX_MALFORMED, m);
  const take = (n) => { if (n < 0 || i + n > buf.length) bad('truncated transaction'); const v = buf.slice(i, i + n); i += n; return v; };
  const byte = () => take(1)[0];
  const sv = () => {
    let n = 0;
    for (let k = 0; k < 3; k++) {
      const b = byte();
      n |= (b & 0x7f) << (7 * k);
      if ((b & 0x80) === 0) { if (k > 0 && b === 0) bad('non-minimal shortvec'); return n; }
    }
    return bad('shortvec too long');
  };
  const nsig = sv();
  if (nsig === 0 || nsig > 16) bad('bad signature count');
  const signatures = [];
  for (let k = 0; k < nsig; k++) signatures.push(take(64));
  const msgStart = i;
  let version = 'legacy';
  if (i < buf.length && (buf[i] & 0x80)) { version = byte() & 0x7f; if (version !== 0) bad(`unsupported transaction version ${version}`); }
  const header = { numRequiredSignatures: byte(), numReadonlySigned: byte(), numReadonlyUnsigned: byte() };
  const nkeys = sv();
  if (nkeys === 0 || nkeys > 64) bad('bad account key count');
  const accountKeys = [];
  for (let k = 0; k < nkeys; k++) accountKeys.push(take(32));
  const recentBlockhash = take(32);
  const nix = sv();
  const instructions = [];
  for (let k = 0; k < nix; k++) {
    const programIdIndex = byte();
    const na = sv();
    const accounts = Array.from(take(na));
    const nd = sv();
    const data = take(nd);
    if (programIdIndex >= accountKeys.length || accounts.some((a) => a >= accountKeys.length)) bad('instruction references an account outside the static keys');
    instructions.push({ programIdIndex, accounts, data });
  }
  let addressTableLookups = 0;
  if (version !== 'legacy') {
    addressTableLookups = sv();
    for (let k = 0; k < addressTableLookups; k++) { take(32); take(sv()); take(sv()); }
  }
  if (i !== buf.length) bad('trailing bytes after message');
  if (signatures.length !== header.numRequiredSignatures) bad('signature count != header.numRequiredSignatures');
  if (header.numRequiredSignatures > accountKeys.length) bad('more signers than keys');
  return { signatures, message: buf.slice(msgStart), version, header, accountKeys, recentBlockhash, instructions, addressTableLookups };
}
