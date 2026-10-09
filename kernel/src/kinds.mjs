/**
 * Receipt kinds → the exact signed bytes and the SIGNED projection (spec/TRUST-KERNEL.md §4, §5).
 * "Only what is signed": each parser rebuilds the signed message from the kind's fixed domain and the
 * signed content, returns the projection taken ONLY from signed bytes, and checks every unsigned field
 * that duplicates signed content (receipt_id, served_message, facts, emitted_at, domain…) for EXACT
 * equality — a mismatch is an integrity failure, never "resolved". Unsigned fields that duplicate nothing
 * are ignored and listed in `ignored_unsigned_fields`; they never influence the verdict.
 */
import { C, KernelError, fail } from './codes.mjs';
import { jcs, jcsSigned } from './canon.mjs';
import { sha256hex, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES } from './crypto.mjs';
import { b64decodeStrict, isHex, isPlainObject, own } from './hygiene.mjs';
import { parseStablecoinReceipt } from './stablecoin.mjs';
import { KINDS, MIDAS_CANON_HEADER, RESERVED_ROUTES, ROUTE_RE, SEAL_SCHEMA, SELF_ATTEST_DOMAIN, SERVED_PREFIX } from './domains.mjs';

const MAX_CANONICAL = 8192;
const MIDAS_REQUIRED = ['address', 'chain_id', 'health_factor', 'threshold', 'collateral_usd', 'debt_usd', 'risk_tier', 'observed_at', 'source', 'snapshot_hash', 'emitted_at'];
const ALWAYS_IGNORED = new Set(['anchor', 'anchors']); // anchor references are hints, verified against consensus

const integrity = (code, detail) => new KernelError(code, detail);
const keyAndSig = (r, pkField = 'public_key', sigField = 'signature') => ({
  pk: b64decodeStrict(r[pkField], ML_DSA_65_PK_BYTES, pkField),
  sig: b64decodeStrict(r[sigField], ML_DSA_65_SIG_BYTES, sigField),
  public_key_b64: r[pkField],
});
const checkAlgorithm = (r) => {
  if (own(r, 'algorithm') && r.algorithm !== 'ml-dsa-65') fail(C.ALGORITHM, `algorithm ${JSON.stringify(r.algorithm)} is not ml-dsa-65`);
};
/** RFC 3339 UTC timestamp as produced by Date#toISOString (ms optional) → unix seconds (floor). */
export function parseSealedAt(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(s)) fail(C.SIGNED_TIME_MALFORMED, 'sealed_at is not an RFC 3339 UTC timestamp');
  const ms = Date.parse(s);
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== s.slice(0, 19)) fail(C.SIGNED_TIME_MALFORMED, 'sealed_at is not a real calendar time');
  return Math.floor(ms / 1000);
}
const decInt = (s, what) => {
  if (typeof s !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(s)) fail(C.CANONICAL_MALFORMED, `${what} is not a canonical decimal integer`);
  const v = Number(s);
  if (!Number.isSafeInteger(v)) fail(C.CANONICAL_MALFORMED, `${what} out of range`);
  return v;
};

/** Parse the MIDAS signed canonical text. Strict: header, `key=value` lines, [a-z_] keys, no duplicates. */
export function parseMidasCanonical(canonical) {
  if (typeof canonical !== 'string' || canonical.length === 0 || canonical.length > MAX_CANONICAL) fail(C.CANONICAL_MALFORMED, 'canonical missing or too long');
  if (/[\r\u0000]/.test(canonical)) fail(C.CANONICAL_MALFORMED, 'canonical contains CR/NUL');
  const [header, ...lines] = canonical.split('\n');
  if (header !== MIDAS_CANON_HEADER) fail(C.CANONICAL_MALFORMED, `canonical header is not ${MIDAS_CANON_HEADER}`);
  const out = Object.create(null);
  for (const l of lines) {
    const m = /^([a-z][a-z0-9_]{0,63})=(.*)$/.exec(l);
    if (!m) fail(C.CANONICAL_MALFORMED, `malformed canonical line ${JSON.stringify(l.slice(0, 40))}`);
    if (own(out, m[1])) fail(C.CANONICAL_MALFORMED, `duplicate canonical key ${m[1]}`);
    out[m[1]] = m[2];
  }
  for (const k of MIDAS_REQUIRED) if (!own(out, k)) fail(C.CANONICAL_MALFORMED, `canonical lacks ${k}`);
  return out;
}

/** Does an unsigned JSON fact equal the signed canonical string? Language-neutral rule (spec §4.2). */
function factEquals(v, s) {
  if (typeof v === 'string') return v === s;
  if (typeof v === 'boolean') return s === String(v);
  if (v === null) return s === 'null';
  if (typeof v === 'number') return /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/.test(s) && Number(s) === v;
  return false;
}

function midas(r) {
  const known = new Set(['canonical', 'signature', 'public_key', 'algorithm', 'receipt_id', 'served_message', 'served_domain', 'domain', 'facts', 'emitted_at', 'content_id', 'snapshot']);
  checkAlgorithm(r);
  const fields = parseMidasCanonical(r.canonical);
  const id = sha256hex(r.canonical);
  const spec = KINDS['midas-alert'];
  const message = spec.message(id);
  if (own(r, 'receipt_id') && r.receipt_id !== id) fail(C.RECEIPT_ID_MISMATCH, 'receipt_id != sha256(canonical)');
  if (own(r, 'content_id') && r.content_id !== id) fail(C.RECEIPT_ID_MISMATCH, 'content_id != sha256(canonical)');
  if (own(r, 'served_message') && r.served_message !== message) fail(C.SIGNED_MESSAGE_MISMATCH, 'served_message != reconstructed signed message');
  if (own(r, 'served_domain') && r.served_domain !== spec.domain) fail(C.DOMAIN_MISMATCH, 'served_domain is not the midas-alert domain');
  if (own(r, 'domain') && r.domain !== MIDAS_CANON_HEADER && r.domain !== spec.domain) fail(C.DOMAIN_MISMATCH, 'domain is neither the canonical header nor the signed domain');
  const signedTime = decInt(fields.emitted_at, 'emitted_at');
  if (own(r, 'emitted_at') && r.emitted_at !== signedTime) fail(C.UNSIGNED_FIELD_MISMATCH, `top-level emitted_at ${JSON.stringify(r.emitted_at)} != signed emitted_at ${signedTime}`);
  if (own(r, 'facts')) {
    if (!isPlainObject(r.facts)) fail(C.UNSIGNED_FIELD_MISMATCH, 'facts is not an object');
    const bad = [];
    for (const k of Object.keys(r.facts)) if (!own(fields, k) || !factEquals(r.facts[k], fields[k])) bad.push(k);
    for (const k of Object.keys(fields)) if (!own(r.facts, k)) bad.push(k);
    if (bad.length) fail(C.UNSIGNED_FIELD_MISMATCH, `facts differ from the signed canonical: ${[...new Set(bad)].slice(0, 12).join(', ')}`);
  }
  // `snapshot` is committed by the SIGNED snapshot_hash = sha256(JCS(snapshot)); it is either exactly that or rejected.
  let committedSnapshot;
  if (own(r, 'snapshot')) {
    if (!isHex(fields.snapshot_hash, 64)) fail(C.SNAPSHOT_MISMATCH, 'signed snapshot_hash is not 64 hex');
    if (sha256hex(jcs(r.snapshot)) !== fields.snapshot_hash) fail(C.SNAPSHOT_MISMATCH, 'sha256(JCS(snapshot)) != signed snapshot_hash');
    committedSnapshot = r.snapshot;
  }
  const ks = keyAndSig(r);
  return {
    kind: 'midas-alert', content_id: id, message, ...ks, signed_time: signedTime,
    signed: { receipt_id: id, canonical_header: MIDAS_CANON_HEADER, ...fields, ...(committedSnapshot !== undefined ? { snapshot: committedSnapshot } : {}) },
    ignored: Object.keys(r).filter((k) => !known.has(k) && !ALWAYS_IGNORED.has(k)),
  };
}

function sealLike(r, kindName) {
  const known = new Set(['algorithm', 'domain', 'content_id', 'public_key', 'signature', 'body']);
  checkAlgorithm(r);
  const spec = KINDS[kindName];
  if (r.domain !== spec.domain) fail(C.DOMAIN_MISMATCH, `seal domain is not the ${kindName} domain`);
  if (!isPlainObject(r.body)) fail(C.INPUT_SHAPE, 'seal body missing or not an object');
  if (r.body.schema !== SEAL_SCHEMA) fail(C.SCHEMA_MISMATCH, `body.schema is not ${SEAL_SCHEMA}`);
  const cid = sha256hex(jcsSigned(r.body));
  if (r.content_id !== cid) fail(C.CONTENT_ID_MISMATCH, 'content_id != sha256(JCS(body)) — body altered');
  const signedTime = own(r.body, 'sealed_at') ? parseSealedAt(r.body.sealed_at) : fail(C.SIGNED_TIME_MALFORMED, 'body.sealed_at missing');
  const ks = keyAndSig(r);
  return {
    kind: kindName, content_id: cid, message: spec.message(cid), ...ks, signed_time: signedTime,
    signed: { content_id: cid, ...r.body },
    ignored: Object.keys(r).filter((k) => !known.has(k) && !ALWAYS_IGNORED.has(k)),
  };
}

function acpVerdict(r) {
  const known = new Set(['decision', 'signed_message', 'signature', 'public_key', 'profile', 'algorithm']);
  checkAlgorithm(r);
  if (!isPlainObject(r.decision)) fail(C.INPUT_SHAPE, 'acp-verdict needs a decision object');
  const digest = sha256hex(jcsSigned(r.decision));
  const message = KINDS['acp-verdict'].message(digest);
  if (own(r, 'signed_message') && r.signed_message !== message) fail(C.SIGNED_MESSAGE_MISMATCH, 'signed_message != served proof over sha256(JCS(decision))');
  const ks = keyAndSig(r);
  return { kind: 'acp-verdict', content_id: digest, message, ...ks, signed_time: null, signed: { digest, ...r.decision }, ignored: Object.keys(r).filter((k) => !known.has(k)) };
}

function servedProof(r) {
  const known = new Set(['domain', 'route_id', 'digest', 'signed_message', 'signature', 'public_key', 'profile', 'algorithm']);
  checkAlgorithm(r);
  if (r.domain !== SERVED_PREFIX) fail(C.DOMAIN_MISMATCH, `served-proof domain is not ${SERVED_PREFIX}`);
  if (typeof r.route_id !== 'string' || !ROUTE_RE.test(r.route_id)) fail(C.ROUTE_MALFORMED, 'route_id must match ^[a-z0-9][a-z0-9-]{0,63}$');
  if (own(RESERVED_ROUTES, r.route_id)) fail(C.ROUTE_RESERVED, `route '${r.route_id}' is reserved for kind ${RESERVED_ROUTES[r.route_id]}`);
  if (!isHex(r.digest, 64)) fail(C.DIGEST_MALFORMED, 'digest must be 64 lowercase hex');
  const message = KINDS['served-proof'].message(r.route_id, r.digest);
  if (own(r, 'signed_message') && r.signed_message !== message) fail(C.SIGNED_MESSAGE_MISMATCH, 'signed_message != domain\\nroute\\ndigest');
  const ks = keyAndSig(r);
  return { kind: 'served-proof', content_id: r.digest, message, ...ks, signed_time: null, signed: { route_id: r.route_id, digest: r.digest }, ignored: Object.keys(r).filter((k) => !known.has(k)) };
}

/** Fields that only one kind carries. A document carrying markers of two kinds is AMBIGUOUS and refused:
 * the kind is fixed by the caller's policy, and a field from another kind can never re-route verification. */
const MARKERS = {
  'midas-alert': ['canonical', 'receipt_id', 'served_message', 'served_domain', 'facts', 'snapshot'],
  'x402-seal': ['body'], 'self-attest-seal': ['body'],
  'acp-verdict': ['decision'],
  'served-proof': ['route_id', 'digest'],
  'latam-stablecoin-receipt': ['transfer_canonical', 'transfer_id', 'transfer'],
};
/** Optional `profile` labels used by the conformance vectors; if present they must name the parsed kind. */
const PROFILE_ALIAS = { 'served-proof': 'x402-served', 'acp-verdict': 'acp-verdict' };

export function checkUnambiguous(r, kind) {
  const families = new Set();
  for (const [k, fields] of Object.entries(MARKERS)) if (fields.some((f) => own(r, f))) families.add(k === 'self-attest-seal' ? 'x402-seal' : k);
  const mine = kind === 'self-attest-seal' ? 'x402-seal' : kind;
  for (const f of families) if (f !== mine) fail(C.KIND_AMBIGUOUS, `document carries ${f} fields while being verified as ${kind}`);
  if (own(r, 'profile') && r.profile !== (PROFILE_ALIAS[kind] ?? kind)) fail(C.KIND_AMBIGUOUS, `profile ${JSON.stringify(r.profile).slice(0, 40)} does not name kind ${kind}`);
}

/**
 * Determine the kind. The CALLER's declared kind wins; inference is shape-based and never reads the
 * domain to choose between differently-trusted kinds except the two seal kinds, whose messages are both
 * rebuilt from fixed domains (self-attest is never authorized by the directory).
 */
export function inferKind(r) {
  if (!isPlainObject(r)) fail(C.INPUT_SHAPE, 'receipt is not a JSON object');
  if (own(r, 'transfer_canonical')) return 'latam-stablecoin-receipt';
  if (own(r, 'canonical')) return 'midas-alert';
  if (own(r, 'body')) return r.domain === SELF_ATTEST_DOMAIN ? 'self-attest-seal' : 'x402-seal';
  if (own(r, 'decision')) return 'acp-verdict';
  if (own(r, 'route_id')) return 'served-proof';
  return fail(C.KIND_UNKNOWN, 'cannot determine the receipt kind from its shape');
}

const PARSERS = {
  'midas-alert': midas,
  'x402-seal': (r) => sealLike(r, 'x402-seal'),
  'self-attest-seal': (r) => sealLike(r, 'self-attest-seal'),
  'acp-verdict': acpVerdict,
  'served-proof': servedProof,
  'latam-stablecoin-receipt': parseStablecoinReceipt,
};

/** @param {object} [ctx]  { tokenRegistry } — kind-specific pinned data (latam-stablecoin-receipt). */
export function parseReceipt(r, declaredKind, ctx = {}) {
  if (!isPlainObject(r)) fail(C.INPUT_SHAPE, 'receipt is not a JSON object');
  const kind = declaredKind ?? inferKind(r);
  const p = PARSERS[kind];
  if (!p) fail(C.KIND_UNKNOWN, `unknown kind ${JSON.stringify(kind)}`);
  checkUnambiguous(r, kind);
  return p(r, ctx);
}

/** On-chain ids of a parsed receipt (fractalai.pqc-receipt-anchor/1). */
export function anchorIds(parsed) {
  return {
    receipt_id: sha256hex(parsed.sig),
    payload_hash: sha256hex(parsed.message),
    kid16: sha256hex(parsed.public_key_b64).slice(0, 16),
  };
}
export { integrity };
