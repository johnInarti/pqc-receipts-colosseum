/**
 * Kind `agent-commerce-receipt` (spec/TRUST-KERNEL.md §13): a protocol-neutral post-quantum receipt that
 * BINDS together, under one ML-DSA-65 signature and one signed time,
 *   - identifiers of a payment produced by some payment protocol (AP2, ERC-8004 job, MCP tool call, PIX…),
 *   - commitments (hashes) to that protocol's own artifacts (mandates, receipts, validation requests), and
 *   - the sha256 of the content that was delivered for that payment.
 *
 *   signed message = "FRACTALAI-agent-commerce-receipt-v1\n" + sha256hex(JCS(commerce))
 *   key use        = "commerce-receipt"   (an x402 or stablecoin key can never sign it, and vice versa)
 *   signed time    = commerce.issued_at  (unix seconds, safe integer)
 *
 * The kernel checks the SHAPE of the body (closed key set, ASCII-only bounded values, safe integers) and the
 * signature/trust of the issuer. It does NOT interpret `payment` or `bindings`: what each key means, and how a
 * relying party re-derives it from the protocol artifacts, is defined by the `profile` (adapters, outside the
 * kernel). A verdict therefore says "this issuer key bound these identifiers and this content hash at T",
 * never "the payment settled" or "the content is correct".
 */
import { C, fail } from './codes.mjs';
import { jcsSigned } from './canon.mjs';
import { sha256hex, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES } from './crypto.mjs';
import { b64decodeStrict, isHex, isPlainObject, own } from './hygiene.mjs';
import { COMMERCE_DOMAIN } from './domains.mjs';

export { COMMERCE_DOMAIN };
export const COMMERCE_VERSION = 'fractalai.agent-commerce/1';
export const COMMERCE_MAX_BYTES = 8192;

const PROTOCOL_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const PROFILE_RE = /^[a-z0-9][a-z0-9.-]{0,63}\/[1-9][0-9]{0,5}$/;
const ENTRY_KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;
const ENTRY_VALUE_RE = /^[\x20-\x7e]{1,512}$/;
const MEDIA_TYPE_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
const BODY_KEYS = ['bindings', 'delivery', 'issued_at', 'payment', 'profile', 'protocol', 'v'];
const DELIVERY_KEYS = new Set(['sha256', 'media_type', 'size']);

const bad = (detail) => fail(C.COMMERCE_MALFORMED, detail);

function entries(obj, what, max) {
  if (!isPlainObject(obj)) bad(`${what} is not an object`);
  const keys = Object.keys(obj);
  if (keys.length > max) bad(`${what} has more than ${max} entries`);
  for (const k of keys) {
    if (!ENTRY_KEY_RE.test(k)) bad(`${what} key ${JSON.stringify(k.slice(0, 40))} does not match ^[a-z][a-z0-9_]{0,63}$`);
    const val = obj[k];
    if (typeof val !== 'string' || !ENTRY_VALUE_RE.test(val)) bad(`${what}.${k} must be 1..512 printable ASCII characters`);
  }
}

/** Strict shape of the signed body (spec §13.2). Returns the signed time. */
export function checkCommerceBody(b) {
  if (!isPlainObject(b)) bad('commerce is not an object');
  const keys = Object.keys(b).sort();
  if (keys.length !== BODY_KEYS.length || keys.some((k, i) => k !== BODY_KEYS[i])) bad(`commerce must have exactly the keys ${BODY_KEYS.join(', ')}`);
  if (b.v !== COMMERCE_VERSION) bad(`commerce.v is not ${COMMERCE_VERSION}`);
  if (typeof b.protocol !== 'string' || !PROTOCOL_RE.test(b.protocol)) bad('commerce.protocol must match ^[a-z0-9][a-z0-9-]{0,31}$');
  if (typeof b.profile !== 'string' || !PROFILE_RE.test(b.profile)) bad('commerce.profile must match <name>/<version>');
  if (!Number.isSafeInteger(b.issued_at) || b.issued_at < 1) bad('commerce.issued_at must be a positive safe integer (unix seconds)');
  entries(b.payment, 'payment', 16);
  entries(b.bindings, 'bindings', 16);
  const d = b.delivery;
  if (!isPlainObject(d)) bad('delivery is not an object');
  for (const k of Object.keys(d)) if (!DELIVERY_KEYS.has(k)) bad(`delivery has an unknown key ${JSON.stringify(k.slice(0, 40))}`);
  if (!isHex(d.sha256, 64)) bad('delivery.sha256 must be 64 lowercase hex');
  if (own(d, 'media_type') && (typeof d.media_type !== 'string' || !MEDIA_TYPE_RE.test(d.media_type))) bad('delivery.media_type is not a lowercase type/subtype');
  if (own(d, 'size') && (!Number.isSafeInteger(d.size) || d.size < 0)) bad('delivery.size must be a non-negative safe integer');
  return b.issued_at;
}

/** Parse a receipt document of kind agent-commerce-receipt (spec §13.3). */
export function parseCommerceReceipt(r) {
  const known = new Set(['commerce', 'commerce_id', 'public_key', 'signature', 'algorithm', 'domain', 'signed_message', 'issued_at', 'profile']);
  if (own(r, 'algorithm') && r.algorithm !== 'ml-dsa-65') fail(C.ALGORITHM, `algorithm ${JSON.stringify(r.algorithm)} is not ml-dsa-65`);
  if (!own(r, 'commerce')) fail(C.INPUT_SHAPE, 'agent-commerce-receipt needs a commerce object');
  const signedTime = checkCommerceBody(r.commerce);
  const canonical = jcsSigned(r.commerce);
  if (new TextEncoder().encode(canonical).length > COMMERCE_MAX_BYTES) bad(`JCS(commerce) exceeds ${COMMERCE_MAX_BYTES} bytes`);
  const id = sha256hex(canonical);
  const message = `${COMMERCE_DOMAIN}\n${id}`;
  if (own(r, 'commerce_id') && r.commerce_id !== id) fail(C.RECEIPT_ID_MISMATCH, 'commerce_id != sha256(JCS(commerce))');
  if (own(r, 'domain') && r.domain !== COMMERCE_DOMAIN) fail(C.DOMAIN_MISMATCH, `domain is not ${COMMERCE_DOMAIN}`);
  if (own(r, 'signed_message') && r.signed_message !== message) fail(C.SIGNED_MESSAGE_MISMATCH, 'signed_message != reconstructed signed message');
  if (own(r, 'issued_at') && r.issued_at !== signedTime) fail(C.UNSIGNED_FIELD_MISMATCH, `top-level issued_at ${JSON.stringify(r.issued_at)} != signed issued_at ${signedTime}`);
  return {
    kind: 'agent-commerce-receipt', content_id: id, message,
    pk: b64decodeStrict(r.public_key, ML_DSA_65_PK_BYTES, 'public_key'),
    sig: b64decodeStrict(r.signature, ML_DSA_65_SIG_BYTES, 'signature'),
    public_key_b64: r.public_key, signed_time: signedTime,
    signed: { commerce_id: id, ...r.commerce },
    ignored: Object.keys(r).filter((k) => !known.has(k) && k !== 'anchor' && k !== 'anchors'),
  };
}

/** Issuer helper (no key material here): the exact message an issuer must sign for a body. */
export function commerceSigningMessage(body) {
  checkCommerceBody(body);
  const canonical = jcsSigned(body);
  if (new TextEncoder().encode(canonical).length > COMMERCE_MAX_BYTES) bad(`JCS(commerce) exceeds ${COMMERCE_MAX_BYTES} bytes`);
  const id = sha256hex(canonical);
  return { commerce_id: id, message: `${COMMERCE_DOMAIN}\n${id}` };
}
