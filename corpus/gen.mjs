#!/usr/bin/env node
/**
 * Generates corpus/vectors/*.json — DETERMINISTIC (fixed seeds, deterministic ML-DSA-65 / Ed25519).
 * Each vector's `expect` is written BY HAND here from the normative spec (spec/TRUST-KERNEL.md), never
 * computed by running the kernel: the corpus is the specification, the kernel is what it tests.
 * Provenance of every adversarial vector is in `source` (red-team PoC ids).
 *   node corpus/gen.mjs
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync } from 'node:fs';
import { parseJsonStrict, sha256hex, jcs, b64encode, BAKED_ROOTS, formatUnits } from '../kernel/src/index.mjs';
import { replayFetch } from './lib/replay.mjs';
import * as S from './lib/synth.mjs';

const here = (p) => new URL(p, import.meta.url);
const read = (p) => parseJsonStrict(readFileSync(here(p), 'utf8'));
const clone = (x) => JSON.parse(JSON.stringify(x));
const OUT = here('./vectors/');
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const NOW = 1791400000;
const FE62 = read('./fixtures/midas-fe62b072.json');
const DIR3 = read('./fixtures/directory-epoch3.json');
const ARC_REC = read('./fixtures/PQCReceiptAnchor-5042-fe62b072.json');
const SOL_REC = read('./fixtures/solana-devnet-fe62b072.json');
const T = (name) => read(`./fixtures/transcripts/${name}.json`).transcript;
const REF = (p) => ({ $ref: p });
const ID = FE62.receipt_id;
const RUNTIME_CODE = T('arc-tx').find((t) => t.method === 'eth_getCode').result;
const ARB = BAKED_ROOTS.anchors.evm['42161'], ARC = BAKED_ROOTS.anchors.evm['5042'];
const TREASURY = '0xc13789e82661635d9cea38a53a0390cf9939ef4f';

// ── levels shorthands ──
const L = (i, a, t, ta = null, f = null) => ({ integrity: i, authentic: a, trusted: t, time_anchored: ta, finalized: f });
const FAIL_I = L(false, false, false), FAIL_A = L(true, false, false), FAIL_T = L(true, true, false), OK = L(true, true, true);
const ALL = ['integrity', 'authentic', 'trusted', 'time_anchored', 'finalized'];

const vectors = [];
function V(id, v) {
  const snake = (o) => (o && typeof o === 'object' && !Array.isArray(o) ? Object.fromEntries(Object.entries(o).map(([k, x]) => [k.replace(/[A-Z]/g, (c) => '_' + c.toLowerCase()), x])) : o);
  if (v.context?.options?.policy) v.context.options.policy = snake(v.context.options.policy);
  const doc = { id, title: v.title, source: v.source ?? [], input: v.input, context: { now: NOW, ...v.context }, expect: v.expect };
  if (!doc.expect || typeof doc.expect.valid !== 'boolean' || !doc.expect.levels) throw new Error(`vector ${id}: incomplete expectation`);
  vectors.push(id);
  writeFileSync(new URL(`${id}.json`, OUT), JSON.stringify(doc, null, 1) + '\n');
}
const fe62 = (mut) => { const r = clone(FE62); if (mut) mut(r); return r; };
const realCtx = (o = {}) => ({ options: { kind: 'midas-alert', ...(o.options || {}) }, directory: REF('fixtures/directory-epoch3.json'), ...o.ctx });

// ═════════════════════════════ POSITIVES (real data) ═════════════════════════════
V('P01-midas-fe62-pinned-root', {
  title: 'Real MIDAS alert fe62b072 + real epoch-3 directory, verified against the BAKED roots',
  input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: realCtx({ options: { expected_id: ID } }),
  expect: { valid: true, levels: OK, trust_basis: 'pinned-root', exit_code: 0 },
});
V('P02-midas-fe62-anchored-arc-and-arbitrum-finalized', {
  title: 'Real receipt anchored on Arc (tx hash ref) and Arbitrum One (block hint) — real RPC answers, all five levels',
  input: { receipt: REF('fixtures/midas-fe62b072.json') },
  context: realCtx({ options: { policy: { require: ALL }, check_anchors: true, anchors: [{ chain_id: 5042, tx_hash: '0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64', log_index: 5 }, { chain_id: 42161, block_number: 511335916 }], rpc: { 'eip155:5042': ['replay://arc'], 'eip155:42161': ['replay://arb1'] } }, ctx: { rpc_transcript: [REF('fixtures/transcripts/arc-tx.json#transcript'), REF('fixtures/transcripts/arb1-logs.json#transcript')] } }),
  expect: { valid: true, levels: L(true, true, true, true, true), trust_basis: 'pinned-root', exit_code: 0 },
});
V('P03-anchor-record-arc-embedded-ref', {
  title: 'Anchor record shape (signed domain + content_id + embedded anchor) verifies; the embedded contract equals the pinned one',
  input: { receipt: ARC_REC.seal }, context: realCtx({ options: { check_anchors: true, rpc: { 'eip155:5042': ['replay://arc'] } }, ctx: { rpc_transcript: [REF('fixtures/transcripts/arc-tx.json#transcript')] } }),
  expect: { valid: true, levels: L(true, true, true, true, true), trust_basis: 'pinned-root' },
});
V('P04-arbitrum-tx-ref', {
  title: 'Arbitrum One anchor located by tx hash + log index',
  input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: realCtx({ options: { check_anchors: true, anchors: [{ chain_id: 42161, tx_hash: '0x37f0254389deed3953aa44333e32eaeb466f28ff41ac9299eb5285599a7a1174', log_index: 5 }], rpc: { 'eip155:42161': ['replay://arb1'] } }, ctx: { rpc_transcript: [REF('fixtures/transcripts/arb1-tx.json#transcript')] } }),
  expect: { valid: true, levels: L(true, true, true, true, true) },
});
V('P05-solana-devnet-allowed-testnet', {
  title: 'Real Solana devnet memo anchor, policy allows test networks (anchor stays marked "test")',
  input: { receipt: SOL_REC.seal }, context: realCtx({ options: { check_anchors: true, anchors: [{ chain: 'solana', cluster: 'devnet', signature: SOL_REC.anchor.signature }], rpc: { 'solana:devnet': ['replay://sol-devnet'] }, policy: { allowTestnetAnchors: true } }, ctx: { rpc_transcript: [REF('fixtures/transcripts/sol-devnet.json#transcript')] } }),
  expect: { valid: true, levels: L(true, true, true, true, true), trust_basis: 'pinned-root' },
});
V('P06-solana-devnet-default-policy-not-a-time-proof', {
  title: 'Same devnet anchor under the default policy: verified facts, but a test network is NOT counted as a time proof',
  input: { receipt: SOL_REC.seal }, context: realCtx({ options: { check_anchors: true, anchors: [{ chain: 'solana', cluster: 'devnet', signature: SOL_REC.anchor.signature }], rpc: { 'solana:devnet': ['replay://sol-devnet'] } }, ctx: { rpc_transcript: [REF('fixtures/transcripts/sol-devnet.json#transcript')] } }),
  expect: { valid: true, levels: L(true, true, true, false, false), codes: ['ANCHOR_TESTNET_NOT_ALLOWED'] },
});
V('P07-cross-rpc-quorum-2-agree', {
  title: 'Two independent RPCs (replayed) return identical anchor facts; quorum 2 satisfied',
  input: { receipt: REF('fixtures/midas-fe62b072.json') },
  context: realCtx({ options: { check_anchors: true, anchors: [{ chain_id: 5042, tx_hash: '0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64', log_index: 5 }], rpc: { 'eip155:5042': ['replay://arc', 'replay://arc-mirror'] }, policy: { rpcQuorum: 2 } }, ctx: { rpc_transcript: [REF('fixtures/transcripts/arc-tx.json#transcript'), ...T('arc-tx').map((t) => ({ ...t, url: 'replay://arc-mirror' }))] } }),
  expect: { valid: true, levels: L(true, true, true, true, true) },
});

// ═════════════════════ real receipt, adversarial (node red-team PoC4 / python F1-F2 / anchor RT-S5) ═════════════════════
const forgedCanon = FE62.canonical.replace('health_factor=1.000872452215302', 'health_factor=4.2').replace('risk_tier=critical', 'risk_tier=safe');
V('N-RTN4a-midas-forged-canonical-recomputed-id', {
  title: 'Mirror rewrites canonical (and recomputes receipt_id/facts) but the caller asked for fe62b072',
  source: ['redteam-node:poc4'], input: { receipt: fe62((r) => { r.canonical = forgedCanon; r.receipt_id = sha256hex(forgedCanon); r.served_message = `FRACTALAI-x402-served-v1\nmidas-alert\n${r.receipt_id}`; r.facts.health_factor = 4.2; r.facts.risk_tier = 'safe'; delete r.snapshot; }) },
  context: realCtx({ options: { expected_id: ID } }), expect: { valid: false, levels: FAIL_I, codes: ['EXPECTED_ID_MISMATCH'], exit_code: 10 },
});
V('N-RTN4b-midas-forged-canonical-no-expected-id', {
  title: 'Same forgery without an expected id: integrity holds, the genuine signature does not cover the new id',
  source: ['redteam-node:poc4'], input: { receipt: fe62((r) => { r.canonical = forgedCanon; r.receipt_id = sha256hex(forgedCanon); r.served_message = `FRACTALAI-x402-served-v1\nmidas-alert\n${r.receipt_id}`; r.facts.health_factor = 4.2; r.facts.risk_tier = 'safe'; delete r.snapshot; }) },
  context: realCtx(), expect: { valid: false, levels: FAIL_A, codes: ['SIGNATURE_INVALID'], exit_code: 11 },
});
V('N-RTN4c-midas-facts-contradict-canonical', {
  title: 'Unsigned facts rewritten (what a webhook consumer reads); canonical untouched', source: ['redteam-node:poc4'],
  input: { receipt: fe62((r) => { r.facts.health_factor = 4.2; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['UNSIGNED_FIELD_MISMATCH'] },
});
V('N-RTN4d-midas-served-message-altered', {
  title: 'served_message points at another route', source: ['redteam-node:poc4', 'redteam-python:F1'],
  input: { receipt: fe62((r) => { r.served_message = r.served_message.replace('midas-alert', 'x402-attest-decision'); }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['SIGNED_MESSAGE_MISMATCH'] },
});
V('N-PYF1-profile-field-reroute', {
  title: 'Tampered MIDAS alert + attacker-added profile:x402-served / route_id / digest fields (verifier must not re-route)', source: ['redteam-python:F1'],
  input: { receipt: fe62((r) => { r.facts.health_factor = 0.42; r.canonical = r.canonical.replace('health_factor=1.000872452215302', 'health_factor=0.42'); Object.assign(r, { profile: 'x402-served', domain: 'FRACTALAI-x402-served-v1', route_id: 'midas-alert', digest: r.receipt_id, signed_message: r.served_message }); }) },
  context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['KIND_AMBIGUOUS'] },
});
V('N-PYF1-profile-field-reroute-as-served-proof', {
  title: 'Same document verified with policy kind served-proof: still ambiguous, refused', source: ['redteam-python:F1'],
  input: { receipt: fe62((r) => { Object.assign(r, { profile: 'x402-served', domain: 'FRACTALAI-x402-served-v1', route_id: 'midas-alert', digest: r.receipt_id, signed_message: r.served_message }); }) },
  context: realCtx({ options: { kind: 'served-proof' } }), expect: { valid: false, levels: FAIL_I, codes: ['KIND_AMBIGUOUS'] },
});
V('N-PYF2a-snapshot-altered', { title: 'Unsigned snapshot rewritten (committed by the signed snapshot_hash)', source: ['redteam-python:F2'], input: { receipt: fe62((r) => { r.snapshot.row.health_factor = 0.5; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['SNAPSHOT_MISMATCH'] } });
V('N-PYF2b-snapshot-replaced', { title: 'snapshot replaced by a nested array', source: ['redteam-python:F2'], input: { receipt: fe62((r) => { r.snapshot = [[[[]]]]; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['SNAPSHOT_MISMATCH'] } });
V('N-PYF2c-extra-unsigned-fact', { title: 'facts carries a key the signer never signed', source: ['redteam-python:F2'], input: { receipt: fe62((r) => { r.facts.recommended_action = 'liquidate-now'; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['UNSIGNED_FIELD_MISMATCH'] } });
V('N-PYF2d-emitted-at-string-zero', { title: 'top-level emitted_at "0" (unsigned copy) contradicts the signed value', source: ['redteam-python:F2', 'redteam-python:F8'], input: { receipt: fe62((r) => { r.emitted_at = '0'; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['UNSIGNED_FIELD_MISMATCH'] } });
V('N-RTS5-redressed-emitted-at', { title: 'Re-dressed receipt: unsigned emitted_at=1700000000 (would bind a forged memo obs)', source: ['redteam-anchor:RT-S5'], input: { receipt: fe62((r) => { r.emitted_at = 1700000000; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['UNSIGNED_FIELD_MISMATCH'] } });
V('N-RTE10a-pk-unpadded', { title: 'Public key without padding (decodes to the same bytes, different kid string)', source: ['redteam-anchor:RT-E10/S6'], input: { receipt: fe62((r) => { r.public_key = r.public_key.replace(/=+$/, ''); }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['B64_NONCANONICAL'] } });
V('N-RTE10b-pk-newline', { title: 'Public key with an embedded newline', source: ['redteam-anchor:RT-E10/S6', 'redteam-python:F3'], input: { receipt: fe62((r) => { r.public_key = r.public_key.slice(0, 40) + '\n' + r.public_key.slice(40); }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['B64_NONCANONICAL'] } });
V('N-RTE10c-sig-trailing-newline', { title: 'Signature with a trailing newline', source: ['redteam-python:F3'], input: { receipt: fe62((r) => { r.signature += '\n'; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['B64_NONCANONICAL'] } });
V('N-algorithm-mismatch', { title: 'algorithm field names another scheme', input: { receipt: fe62((r) => { r.algorithm = 'ml-dsa-44'; }) }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['ALGORITHM'] } });
V('N-kind-not-declared', { title: 'Caller policy names no kind — the document never chooses', source: ['redteam-python:F1'], input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: { options: {}, directory: REF('fixtures/directory-epoch3.json') }, expect: { valid: false, levels: FAIL_I, codes: ['KIND_UNKNOWN'] } });
V('N-kind-policy-seal-gets-midas', { title: 'Policy expects x402 seals only; a MIDAS alert is refused', input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: realCtx({ options: { kind: undefined, kinds: ['x402-seal', 'self-attest-seal'] } }), expect: { valid: false, levels: FAIL_I, codes: ['KIND_NOT_ALLOWED'] } });

// ── raw-text hygiene (python F4/F7, node poc7, N1) ──
const FE62_TEXT = JSON.stringify(FE62);
V('N-PYF4-nan-token', { title: 'NaN token (not RFC 8259 JSON)', source: ['redteam-python:F4'], input: { receipt_text: FE62_TEXT.slice(0, -1) + ',"x_note":NaN}' }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_INVALID'] } });
V('N-PYF4-infinity-token', { title: 'Infinity token', source: ['redteam-python:F4'], input: { receipt_text: FE62_TEXT.slice(0, -1) + ',"x_note":-Infinity}' }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_INVALID'] } });
V('N-RTN7-duplicate-key', { title: 'Duplicate object key (parsers disagree on first/last wins)', source: ['redteam-node:poc7', 'redteam-action:RT-12'], input: { receipt_text: FE62_TEXT.slice(0, -1) + `,"emitted_at":${FE62.emitted_at}}` }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_DUPLICATE_KEY'] } });
V('N-PYF7-deep-nesting', { title: '100000-deep array (must be a rejection, not a crash)', source: ['redteam-python:F7', 'redteam-node:poc7'], input: { receipt_text: '{"canonical":' + '['.repeat(100000) + ']'.repeat(100000) + '}' }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_TOO_DEEP'] } });
V('N-RTN7-lone-surrogate', { title: 'Lone UTF-16 surrogate escape (not representable in UTF-8)', source: ['redteam-node:poc7'], input: { receipt_text: FE62_TEXT.slice(0, -1) + ',"x":"\\ud800"}' }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_LONE_SURROGATE'] } });
V('N-bom', { title: 'Leading byte-order mark', input: { receipt_text: '\ufeff' + FE62_TEXT }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_INVALID'] } });
V('N-trailing-garbage', { title: 'Trailing bytes after the JSON value', input: { receipt_text: FE62_TEXT + ' {}' }, context: realCtx(), expect: { valid: false, levels: FAIL_I, codes: ['JSON_INVALID'] } });

// ── directory attacks on the REAL receipt (node poc5, action RT-9/11/12, python F10/F11) ──
const dirMut = (m) => { const d = clone(DIR3); m(d); return d; };
V('N-RTN5a-unsigned-directory', { title: 'Directory without signature', source: ['redteam-node:poc5'], input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: { options: { kind: 'midas-alert' }, directory: dirMut((d) => { delete d.signature; }) }, expect: { valid: false, levels: FAIL_T, trust_basis: 'none', codes: ['DIRECTORY_INVALID'] } });
V('N-RTN5b-directory-tampered-status', { title: 'Reserved key flipped to active without re-signing (root no longer recomputes)', source: ['redteam-node:poc1'], input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: { options: { kind: 'midas-alert' }, directory: dirMut((d) => { d.keys[2].status = 'active'; }) }, expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_INVALID'] } });
for (const [n, k] of [['null', null], ['empty-string', ''], ['zero', 0], ['false', false], ['object', {}]]) {
  V(`N-PYF11-directory-keys-${n}`, { title: `directory keys = ${JSON.stringify(k)}`, source: ['redteam-python:F11'], input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: { options: { kind: 'midas-alert' }, directory: dirMut((d) => { d.keys = k; }) }, expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_INVALID'] } });
}
V('N-RTA11-directory-epoch-string', { title: 'epoch as a string', source: ['redteam-action:RT-11'], input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: { options: { kind: 'midas-alert' }, directory: dirMut((d) => { d.epoch = '3'; }) }, expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_INVALID'] } });
V('N-RTA-directory-trust-tls-override', { title: 'allowTlsDirectory override: same real directory, but trust_basis must say "tls" (not pinned)', input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: { options: { kind: 'midas-alert', allow_tls_directory: true }, directory: REF('fixtures/directory-epoch3.json') }, expect: { valid: true, levels: OK, trust_basis: 'tls' } });

// ═══════════════════════ synthetic test PKI (directory lifecycle, chains, kinds) ═══════════════════════
const GOV = S.mlKey('governance'), OTHER_GOV = S.mlKey('other-governance');
const K = { A: S.mlKey('active'), R: S.mlKey('retiring'), V: S.mlKey('revoked'), RX: S.mlKey('revoked-no-date'), S: S.mlKey('reserved'), G: S.mlKey('gov-use'), N: S.mlKey('not-yet'), B: S.mlKey('added-epoch5'), X: S.mlKey('attacker') };
const E3KEYS = [
  { key: K.A, status: 'active', not_before: 1790000000 },
  { key: K.R, status: 'retiring', not_before: 1780000000, not_after: 1790600000 },
  { key: K.V, status: 'revoked', not_before: 1780000000, revoked_at: 1791000000 },
  { key: K.RX, status: 'revoked', not_before: 1780000000 },
  { key: K.S, status: 'reserved' },
  { key: K.G, status: 'active', use: 'key-directory-governance', not_before: 0 },
  { key: K.N, status: 'active', not_before: 1799999999 },
];
const D3 = S.directory(E3KEYS, GOV, { epoch: 3, prevRoot: sha256hex('epoch-2') });
const E4KEYS = E3KEYS.map((k) => (k.key === K.R ? { ...k, status: 'retired' } : k));
const D4 = S.directory(E4KEYS, GOV, { epoch: 4, prevRoot: D3.root });
const D5 = S.directory([...E4KEYS, { key: K.B, status: 'active', not_before: 1791000000 }], GOV, { epoch: 5, prevRoot: D4.root });
const TR = S.testRoots(GOV, D3);
const synth = (o = {}) => ({ roots: TR, directory: D3, options: { ...(o.options?.kinds ? {} : { kind: 'midas-alert' }), ...(o.options || {}) }, ...(o.ctx || {}) });
const OKO = { ...OK }; // trust_basis 'override' for every test-roots vector

const mA = S.midasReceipt(K.A);
V('P10-synthetic-midas-active-key', { title: 'Synthetic MIDAS alert, active test key, test roots (override)', input: { receipt: mA }, context: synth(), expect: { valid: true, levels: OKO, trust_basis: 'override' } });
V('P11-retiring-key-inside-window', { title: 'Retiring key, SIGNED emitted_at inside [not_before, not_after]', input: { receipt: S.midasReceipt(K.R, S.MIDAS_FIELDS({ emitted_at: '1790500000' })) }, context: synth(), expect: { valid: true, levels: OKO } });
V('N-RTE8-retiring-key-after-not-after', { title: 'Retiring key, signed emitted_at after not_after', source: ['redteam-anchor:RT-E8', 'redteam-python:F8'], input: { receipt: S.midasReceipt(K.R, S.MIDAS_FIELDS({ emitted_at: '1790700000' })) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_EXPIRED'] } });
V('N-RTN1-reserved-key', { title: 'Reserved (never activated) key signs a receipt', source: ['redteam-node:poc1'], input: { receipt: S.midasReceipt(K.S) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_STATUS_RESERVED'] } });
V('N-RTN1-revoked-key-no-anchor', { title: 'Revoked key, signed time before revoked_at but no consensus time proof', source: ['redteam-node:poc1', 'redteam-anchor:RT-E8'], input: { receipt: S.midasReceipt(K.V) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_REVOKED'] } });
V('N-RTN1-revoked-key-without-date', { title: 'Revoked key without revoked_at — nothing it signed is trusted', source: ['redteam-node:poc1'], input: { receipt: S.midasReceipt(K.RX) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_REVOKED'] } });
V('N-RTN5e-governance-use-key', { title: 'Key whose use is key-directory-governance signs a receipt', source: ['redteam-node:poc5'], input: { receipt: S.midasReceipt(K.G) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_USE_MISMATCH'] } });
V('N-RTN5d-key-not-yet-valid', { title: 'Active key whose not_before is after the signed time', source: ['redteam-node:poc5', 'redteam-anchor:RT-E9'], input: { receipt: S.midasReceipt(K.N) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_NOT_YET_VALID'] } });
V('N-attacker-key-not-listed', { title: 'Self-consistent receipt by an attacker key (signature valid, key not in directory)', source: ['redteam-node:poc7'], input: { receipt: S.midasReceipt(K.X) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['KEY_NOT_LISTED'] } });
V('N-signed-time-in-future', { title: 'Signed emitted_at far in the future', input: { receipt: S.midasReceipt(K.A, S.MIDAS_FIELDS({ emitted_at: String(NOW + 86400) })) }, context: synth(), expect: { valid: false, levels: FAIL_T, codes: ['SIGNED_TIME_IN_FUTURE'] } });
const mA2 = S.midasReceipt(K.A, S.MIDAS_FIELDS({ health_factor: '1.5' }));
V('N-RTA8-expected-id-other-genuine-receipt', { title: 'Caller requested receipt A, a genuine receipt B by the same key is served', source: ['redteam-action:RT-8'], input: { receipt: mA2 }, context: synth({ options: { expected_id: mA.receipt_id } }), expect: { valid: false, levels: FAIL_I, codes: ['EXPECTED_ID_MISMATCH'] } });

// directory chain / anti-rollback
V('P12-directory-chain-epoch5-via-history', { title: 'Checkpoint epoch 3 → epoch 4 (history) → epoch 5, append-only, same governance key', input: { receipt: S.midasReceipt(K.B, S.MIDAS_FIELDS({ emitted_at: '1791100000' })) }, context: synth({ ctx: { directory: D5, directory_history: [D4] } }), expect: { valid: true, levels: OKO } });
V('N-chain-gap', { title: 'Epoch 5 without epoch 4: continuity from the pinned checkpoint is unverifiable', input: { receipt: S.midasReceipt(K.A) }, context: synth({ ctx: { directory: D5 } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_CHAIN_GAP'] } });
const D4bad = S.directory(E4KEYS, GOV, { epoch: 4, prevRoot: sha256hex('fork') });
V('N-chain-break', { title: 'Epoch 4 whose prev_root is not the checkpoint root', input: { receipt: S.midasReceipt(K.A) }, context: synth({ ctx: { directory: D4bad } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_CHAIN_BREAK'] } });
V('N-rollback', { title: 'Epoch 3 directory presented to a verifier pinned at epoch 4', input: { receipt: S.midasReceipt(K.A) }, context: { ...synth(), roots: S.testRoots(GOV, D4) }, expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_ROLLBACK'] } });
const D3fork = S.directory([...E3KEYS, { key: K.X, status: 'active', not_before: 0 }], GOV, { epoch: 3, prevRoot: sha256hex('epoch-2') });
V('N-equivocation', { title: 'A second, different epoch-3 directory adds the attacker key (split view)', input: { receipt: S.midasReceipt(K.X) }, context: synth({ ctx: { directory: D3fork } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_EQUIVOCATION'] } });
const D4drop = S.directory(E4KEYS.filter((k) => k.key !== K.V), GOV, { epoch: 4, prevRoot: D3.root });
V('N-not-append-only-removed-key', { title: 'Epoch 4 silently drops a revoked key (append-only violated)', input: { receipt: S.midasReceipt(K.A) }, context: { ...synth(), directory: D4drop, directory_history: [D3] }, expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_NOT_APPEND_ONLY'] } });
const D4unrevoke = S.directory(E3KEYS.map((k) => (k.key === K.V ? { ...k, status: 'active', revoked_at: undefined } : k)), GOV, { epoch: 4, prevRoot: D3.root });
V('N-not-append-only-unrevoke', { title: 'Epoch 4 turns a revoked key back to active', input: { receipt: S.midasReceipt(K.V, S.MIDAS_FIELDS({ emitted_at: '1791200000' })) }, context: { ...synth(), directory: D4unrevoke, directory_history: [D3] }, expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_NOT_APPEND_ONLY'] } });
const D3other = S.directory(E3KEYS, OTHER_GOV, { epoch: 3, prevRoot: sha256hex('epoch-2') });
V('N-RTA9-directory-other-governance', { title: 'Well-formed directory signed by a governance key that is not pinned', source: ['redteam-action:RT-9', 'redteam-node:poc5'], input: { receipt: S.midasReceipt(K.A) }, context: synth({ ctx: { directory: D3other } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_SIGNER_NOT_PINNED'] } });
const D3dup = S.directory(E3KEYS, GOV, { epoch: 3, prevRoot: sha256hex('epoch-2'), mutateKeys: (ks) => ks.push({ ...ks[2], status: 'active' }) });
V('N-RTA12-duplicate-key-entry', { title: 'Same key listed twice (revoked + active) — ambiguous status', source: ['redteam-action:RT-12'], input: { receipt: S.midasReceipt(K.V) }, context: synth({ ctx: { directory: D3dup } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_INVALID'] } });
const D3str = S.directory(E3KEYS, GOV, { epoch: 3, prevRoot: sha256hex('epoch-2'), mutateKeys: (ks) => { ks[1].not_after = 'soon'; } });
V('N-PYF8b-not-after-unparsable', { title: 'Retiring key with not_after "soon" (signed!) — malformed lifecycle is never "no expiry"', source: ['redteam-python:F8b', 'redteam-node:poc5'], input: { receipt: S.midasReceipt(K.R) }, context: synth({ ctx: { directory: D3str } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_INVALID'] } });
const D3nostatus = S.directory(E3KEYS, GOV, { epoch: 3, prevRoot: sha256hex('epoch-2'), mutateKeys: (ks) => { delete ks[0].status; } });
V('N-RTN5-status-missing', { title: 'Key entry without status (old "epoch-1 shape" leniency)', source: ['redteam-node:poc5'], input: { receipt: S.midasReceipt(K.A) }, context: synth({ ctx: { directory: D3nostatus } }), expect: { valid: false, levels: FAIL_T, codes: ['DIRECTORY_INVALID'] } });
V('N-RTA5-empty-trusted-keys', { title: 'trustedKeys override present but empty — never falls back to anything', source: ['redteam-action:RT-5'], input: { receipt: mA }, context: synth({ options: { trusted_keys: [] } }), expect: { valid: false, levels: FAIL_T, codes: ['NO_TRUST_SOURCE'] } });
V('P13-trusted-keys-override', { title: 'Pinned key set override (no directory) — trust_basis "override"', input: { receipt: mA }, context: { options: { kind: 'midas-alert', trusted_keys: [K.A.pk] } }, expect: { valid: true, levels: OK, trust_basis: 'override' } });
V('N-no-directory', { title: 'No directory and no trusted keys', input: { receipt: mA }, context: { options: { kind: 'midas-alert' } }, expect: { valid: false, levels: FAIL_T, codes: ['NO_TRUST_SOURCE'] } });

// ── seals / served proofs / acp verdict (node poc2, poc7; python F1b; action RT-13) ──
const seal = S.sealReceipt(K.A, S.sealBody());
V('P14-x402-notary-seal', { title: 'Notary x402 settlement seal by the active test key', input: { receipt: seal }, context: synth({ options: { kind: 'x402-seal' } }), expect: { valid: true, levels: OKO } });
const acp = read('../conformance/vectors/acp-verdict.json');
const [d1, route, dg] = acp.valid.signed_message.split('\n');
V('N-RTN2a-acp-verdict-rewrapped-as-seal', { title: 'Public acp-verdict signature re-wrapped as a seal (attacker-chosen domain)', source: ['redteam-node:poc2'], input: { receipt: { algorithm: 'ml-dsa-65', domain: `${d1}\n${route}`, content_id: dg, public_key: acp.valid.public_key, signature: acp.valid.signature, body: acp.valid.decision } }, context: { options: { kinds: ['x402-seal', 'self-attest-seal'], trusted_keys: [acp.trusted_public_key] } }, expect: { valid: false, levels: FAIL_I, codes: ['DOMAIN_MISMATCH'] } });
V('N-RTN2b-acp-verdict-rewrapped-notary-domain', { title: 'Same, with the domain switched to the notary domain and the decision as body', source: ['redteam-node:poc2'], input: { receipt: { algorithm: 'ml-dsa-65', domain: 'FRACTALAI-x402-served-v1\nx402-witness', content_id: dg, public_key: acp.valid.public_key, signature: acp.valid.signature, body: acp.valid.decision } }, context: { options: { kind: 'x402-seal', trusted_keys: [acp.trusted_public_key] } }, expect: { valid: false, levels: FAIL_I, codes: ['SCHEMA_MISMATCH'] } });
const acpBody = { ...acp.valid.decision, schema: 'fractalai.x402-settlement-seal/0.1', sealed_at: '2026-10-01T00:00:00.000Z' };
V('N-RTN2c-acp-verdict-rewrapped-with-schema', { title: 'Re-wrap with a schema-conformant body: content_id recomputes but the signature does not cover the notary message', source: ['redteam-node:poc2'], input: { receipt: { algorithm: 'ml-dsa-65', domain: 'FRACTALAI-x402-served-v1\nx402-witness', content_id: sha256hex(jcs(acpBody)), public_key: acp.valid.public_key, signature: acp.valid.signature, body: acpBody } }, context: { options: { kind: 'x402-seal', trusted_keys: [acp.trusted_public_key] } }, expect: { valid: false, levels: FAIL_A, codes: ['SIGNATURE_INVALID'] } });
V('P15-acp-verdict-conformance-vector', { title: 'Public acp-verdict golden vector as its own kind (override key set)', input: { receipt: acp.valid }, context: { options: { kind: 'acp-verdict', trusted_keys: [acp.trusted_public_key] } }, expect: { valid: true, levels: OK, trust_basis: 'override' } });
const xs = read('../conformance/vectors/x402-served.json');
V('P16-served-proof-conformance-vector', { title: 'Public x402-served golden vector as a served-proof (override key set)', input: { receipt: xs.valid }, context: { options: { kind: 'served-proof', trusted_keys: [xs.trusted_public_key] } }, expect: { valid: true, levels: OK } });
V('N-PYF1b-served-proof-as-midas', { title: 'A genuine served proof for route verify-agent presented where a MIDAS alert is expected', source: ['redteam-python:F1b'], input: { receipt: xs.valid }, context: { options: { kind: 'midas-alert', trusted_keys: [xs.trusted_public_key] } }, expect: { valid: false, levels: FAIL_I, codes: ['KIND_AMBIGUOUS'] } });
V('N-RTN7a-served-proof-foreign-domain', { title: 'Trusted key signs a message under a non-FractalAI domain', source: ['redteam-node:poc7'], input: { receipt: S.servedProof(K.A, 'verify-agent', '00'.repeat(32), 'SOME-OTHER-PROTOCOL-v9') }, context: synth({ options: { kind: 'served-proof' } }), expect: { valid: false, levels: FAIL_I, codes: ['DOMAIN_MISMATCH'] } });
V('N-RTN7b-served-proof-digest-not-hex', { title: 'digest is not 64 hex', source: ['redteam-node:poc7'], input: { receipt: S.servedProof(K.A, 'x', 'not-hex\u0000') }, context: synth({ options: { kind: 'served-proof' } }), expect: { valid: false, levels: FAIL_I, codes: ['DIGEST_MALFORMED'] } });
V('N-served-proof-reserved-route', { title: 'Generic served proof for the reserved midas-alert route', input: { receipt: S.servedProof(K.A, 'midas-alert', mA.receipt_id) }, context: synth({ options: { kind: 'served-proof' } }), expect: { valid: false, levels: FAIL_I, codes: ['ROUTE_RESERVED'] } });
V('N-PYN2-route-id-array', { title: 'route_id given as an array (String() coercion must not happen)', source: ['redteam-python:N2'], input: { receipt: { ...S.servedProof(K.A, 'verify-agent', '00'.repeat(32)), route_id: ['verify-agent'] } }, context: synth({ options: { kind: 'served-proof' } }), expect: { valid: false, levels: FAIL_I, codes: ['ROUTE_MALFORMED'] } });
V('N-RTA13-served-proof-retiring-unsigned-time', { title: 'Retiring key + served proof (no signed time) + unsigned top-level emitted_at inside the window', source: ['redteam-action:RT-13'], input: { receipt: { ...S.servedProof(K.R, 'verify-agent', '11'.repeat(32)), emitted_at: 1790500000 } }, context: synth({ options: { kind: 'served-proof' } }), expect: { valid: false, levels: FAIL_T, codes: ['KEY_NEEDS_SIGNED_TIME'] } });
V('N-RTN7c-attacker-notary-seal', { title: 'Attacker key mints a "notary" seal: authentic bytes, untrusted key', source: ['redteam-node:poc7'], input: { receipt: S.sealReceipt(K.X, S.sealBody({ amount: '999999999', payer: '0xVictim' })) }, context: synth({ options: { kind: 'x402-seal' } }), expect: { valid: false, levels: FAIL_T, codes: ['KEY_NOT_LISTED'] } });
V('N-self-attest-not-directory-trusted', { title: 'Self-attest seal by a directory key: the directory never authorizes seller self-attestation', input: { receipt: S.sealReceipt(K.A, S.sealBody(), 'FRACTALAI-x402-self-attest-v1') }, context: synth({ options: { kinds: ['x402-seal', 'self-attest-seal'] } }), expect: { valid: false, levels: FAIL_T, codes: ['SELF_ATTEST_NOT_TRUSTED'] } });
V('N-seal-unsafe-integer', { title: 'Seal body with a number beyond 2^53 (runtime-dependent canonicalisation)', source: ['redteam-node:poc7'], input: { receipt_text: JSON.stringify(seal).replace('"success":true', '"success":true,"n":9007199254740993') }, context: synth({ options: { kind: 'x402-seal' } }), expect: { valid: false, levels: FAIL_I, codes: ['SIGNED_JSON_NUMBER'] } });
V('N-seal-body-altered', { title: 'Seal body edited after signing', input: { receipt: { ...seal, body: { ...seal.body, amount: '1' } } }, context: synth({ options: { kind: 'x402-seal' } }), expect: { valid: false, levels: FAIL_I, codes: ['CONTENT_ID_MISMATCH'] } });
V('N-seal-sealed-at-malformed', { title: 'sealed_at not RFC 3339 UTC', input: { receipt: S.sealReceipt(K.A, S.sealBody({ sealed_at: '1 Oct 2026' })) }, context: synth({ options: { kind: 'x402-seal' } }), expect: { valid: false, levels: FAIL_I, codes: ['SIGNED_TIME_MALFORMED'] } });
// N1: JSON key-cache confusion — signed over key "\\", delivered as "A" (= "A"). Every RFC 8259 parser reads "A".
const n1Body = S.sealBody({ '\\': 'refund-to-attacker' });
const n1 = S.sealReceipt(K.A, n1Body);
V('N-PYN1-json-key-cache-confusion', { title: 'Seal signed over a body key "\\\\", delivered with that key spelled \\u0041; runners prime the engine JSON parser first', source: ['redteam-python:N1'], input: { receipt_text: JSON.stringify(n1).replace('"\\\\":"refund-to-attacker"', '"\\u0041":"refund-to-attacker"'), prime_json: ['{" ":{},"\\\\":{}}', '{"\\u2028":{},"\\\\":{}}', '{"schema":"x","\\\\":"w"}'] }, context: synth({ options: { kind: 'x402-seal' } }), expect: { valid: false, levels: FAIL_I, codes: ['CONTENT_ID_MISMATCH'] } });

// ═════════════════════════ EVM anchors (anchor red-team RT-E*, node poc3) ═════════════════════════
const arcRef = { chain_id: 5042, tx_hash: '0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64', log_index: 5 };
const arcRpc = { 'eip155:5042': ['replay://arc'] };
const arcT = (mut) => { const t = clone(T('arc-tx')); mut(t); return t; };
const rcLog = (t) => t.find((x) => x.method === 'eth_getTransactionReceipt').result.logs.find((l) => l.topics[0] === '0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184');
const anchored = (title, src, transcript, codes, levels = L(true, true, true, false, false), extra = {}) => ({
  title, source: src, input: { receipt: REF('fixtures/midas-fe62b072.json') },
  context: realCtx({ options: { check_anchors: true, anchors: [extra.ref ?? arcRef], rpc: extra.rpc ?? arcRpc, policy: { require: ['integrity', 'authentic', 'trusted', 'time_anchored'], ...(extra.policy || {}) } }, ctx: { rpc_transcript: transcript } }),
  expect: { valid: extra.valid ?? false, levels, codes, ...(extra.exit ? { exit_code: extra.exit } : {}) },
});
V('N-RTE2a-lookalike-contract-ref', anchored('Anchor reference names a look-alike contract (attacker deploys an emitter with a back-dated anchoredAt)', ['redteam-anchor:RT-E2', 'redteam-node:poc3'], [REF('fixtures/transcripts/arc-tx.json#transcript')], ['ANCHOR_CONTRACT_NOT_PINNED'], undefined, { ref: { ...arcRef, contract: '0x' + 'ee'.repeat(20) }, exit: 13 }));
V('N-RTE2b-codehash-lie', anchored('RPC serves different code at the pinned address', ['redteam-anchor:RT-E2'], arcT((t) => { t.find((x) => x.method === 'eth_getCode').result = '0x6080604052'; }), ['ANCHOR_CODEHASH_MISMATCH']));
V('N-RTE2c-chain-not-pinned', anchored('Anchor on a chain with no pinned deployment (local/test chain)', ['redteam-anchor:RT-E2'], [], ['ANCHOR_CHAIN_NOT_PINNED'], undefined, { ref: { chain_id: 31337, contract: '0x' + '11'.repeat(20) }, rpc: {} }));
V('N-RTE3-squatted', anchored('receiptId occupied by a stranger with a garbage payloadHash', ['redteam-anchor:RT-E3'], arcT((t) => { rcLog(t).topics[2] = '0x' + 'ee'.repeat(32); }), ['ANCHOR_SQUATTED']));
const squatT = arcT((t) => { rcLog(t).topics[2] = '0x' + 'ee'.repeat(32); });
V('P17-multi-anchor-rescues-squat', { title: 'Squatted on Arc, genuine on Arbitrum One: anchors[] — one verified anchor is enough', source: ['redteam-anchor:RT-E3'], input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: realCtx({ options: { check_anchors: true, anchors: [arcRef, { chain_id: 42161, block_number: 511335916 }], rpc: { ...arcRpc, 'eip155:42161': ['replay://arb1'] }, policy: { require: ALL } }, ctx: { rpc_transcript: [...squatT, REF('fixtures/transcripts/arb1-logs.json#transcript')] } }), expect: { valid: true, levels: L(true, true, true, true, true), codes: ['ANCHOR_SQUATTED'] } });
const stranger = '0x' + '77'.repeat(20);
const strangerT = arcT((t) => { const l = rcLog(t); l.data = l.data.slice(0, 66) + stranger.slice(2).padStart(64, '0') + l.data.slice(130); });
V('P18-front-run-copy-still-a-time-proof', anchored('A stranger anchored the GENUINE bytes first: existence-by-time still holds (anchorer reported)', ['redteam-anchor:RT-E3b'], strangerT, [], L(true, true, true, true, true), { valid: true }));
V('N-RTE3b-front-run-copy-known-anchorer-policy', anchored('Same, policy requires a known FractalAI anchorer', ['redteam-anchor:RT-E3b'], strangerT, ['ANCHOR_ANCHORER_UNKNOWN'], undefined, { policy: { requireKnownAnchorer: true } }));
V('N-RTE4a-event-time-vs-header', anchored('Header timestamp differs from the event anchoredAt (lying RPC / look-alike)', ['redteam-anchor:RT-E4', 'redteam-node:poc3'], arcT((t) => { t.find((x) => x.method === 'eth_getBlockByNumber' && x.params[0] !== 'finalized').result.timestamp = '0x64b8a3c0'; }), ['ANCHOR_TIME_MISMATCH']));
V('N-RTE4b-non-canonical-block-hash', anchored('log.blockHash is not the canonical hash of that block', ['redteam-anchor:RT-E4'], arcT((t) => { rcLog(t).blockHash = '0x' + '01'.repeat(32); }), ['ANCHOR_BLOCK_MISMATCH']));
V('N-RTE4c-removed-log', anchored('log.removed = true (reorged out)', ['redteam-anchor:RT-E4'], arcT((t) => { rcLog(t).removed = true; }), ['ANCHOR_LOG_REMOVED']));
V('N-RTE5a-observed-at-not-signed-time', anchored('On-chain observedAt (1) differs from the SIGNED emitted_at', ['redteam-anchor:RT-E5'], arcT((t) => { const l = rcLog(t); l.data = '0x' + '1'.padStart(64, '0') + l.data.slice(66); }), ['ANCHOR_OBSERVED_AT_MISMATCH']));
V('N-RTN3b-malformed-block-number', anchored('log.blockNumber "0xZZ" (NaN comparison used to fail open)', ['redteam-node:poc3'], arcT((t) => { rcLog(t).blockNumber = '0xZZ'; }), ['ANCHOR_LOG_MALFORMED']));
V('N-RTE-wrong-chain', anchored('RPC of another chain answers for chain 5042', ['redteam-anchor:RT-S2 (EVM analogue)'], arcT((t) => { t.find((x) => x.method === 'eth_chainId').result = '0xa4b1'; }), ['ANCHOR_WRONG_CHAIN']));
V('N-RTE6-cross-rpc-disagreement', anchored('Second RPC reports another block hash', ['redteam-anchor:RT-E6'], [REF('fixtures/transcripts/arc-tx.json#transcript'), ...arcT((t) => { rcLog(t).blockHash = '0x' + '0f'.repeat(32); t.find((x) => x.method === 'eth_getBlockByNumber' && x.params[0] !== 'finalized').result.hash = '0x' + '0f'.repeat(32); }).map((x) => ({ ...x, url: 'replay://arc-liar' }))], ['RPC_DISAGREEMENT'], undefined, { rpc: { 'eip155:5042': ['replay://arc', 'replay://arc-liar'] } }));
V('N-RTE6-quorum-not-met', anchored('Policy requires 2 RPCs, one configured', ['redteam-anchor:RT-E6'], [REF('fixtures/transcripts/arc-tx.json#transcript')], ['RPC_QUORUM'], undefined, { policy: { rpcQuorum: 2 } }));
V('N-RTE7-not-finalized', { ...anchored('Anchor block above the finalized tag; policy requires finalized', ['redteam-anchor:RT-E7'], arcT((t) => { t.find((x) => x.method === 'eth_getBlockByNumber' && x.params[0] === 'finalized').result.number = '0x16f5000'; }), ['NOT_FINALIZED'], L(true, true, true, true, false), { policy: { require: ALL } }), expect: { valid: false, levels: L(true, true, true, true, false), codes: ['NOT_FINALIZED'], exit_code: 14 } });
V('N-confirmations', anchored('Fewer confirmations than policy', [], [REF('fixtures/transcripts/arc-tx.json#transcript')], ['ANCHOR_CONFIRMATIONS'], undefined, { policy: { minConfirmations: 1000000000 } }));
V('N-no-anchor-reference', anchored('Policy requires a time proof, no anchor reference given', [], [], ['NO_ANCHOR'], undefined, { ref: undefined }));
// fix N-no-anchor-reference: anchors = []
{ const p = new URL('N-no-anchor-reference.json', OUT); const d = JSON.parse(readFileSync(p, 'utf8')); d.context.options.anchors = []; writeFileSync(p, JSON.stringify(d, null, 1) + '\n'); }

// revoked key + consensus time proof (synthetic chain 42161 node with the real runtime code)
const vRec = S.midasReceipt(K.V, S.MIDAS_FIELDS({ emitted_at: '1790500000' }));
const vIds = S.idsOf(vRec.signature, vRec.served_message, vRec.public_key);
const synT = (o) => S.evmTranscript({ url: 'replay://synthetic-arb1', chainId: 42161, contract: ARB.contract, code: RUNTIME_CODE, anchoredBy: TREASURY, ...o });
const synAnchor = (bn) => ({ chain_id: 42161, block_number: bn });
V('P19-revoked-key-anchored-before-revocation', { title: 'Revoked key (revoked_at 1791000000), receipt anchored at 1790600000 — consensus time proves pre-revocation existence', source: ['redteam-anchor:RT-E8'], input: { receipt: vRec }, context: synth({ options: { check_anchors: true, anchors: [synAnchor(600000000)], rpc: { 'eip155:42161': ['replay://synthetic-arb1'] } }, ctx: { rpc_transcript: synT({ ids: vIds, observedAt: 1790500000, blockNumber: 600000000, blockTime: 1790600000 }) } }), expect: { valid: true, levels: L(true, true, true, true, true), trust_basis: 'override' } });
V('N-RTE8-revoked-key-anchored-after-revocation', { title: 'Same revoked key, anchor after revoked_at', source: ['redteam-anchor:RT-E8'], input: { receipt: vRec }, context: synth({ options: { check_anchors: true, anchors: [synAnchor(600000001)], rpc: { 'eip155:42161': ['replay://synthetic-arb1'] } }, ctx: { rpc_transcript: synT({ ids: vIds, observedAt: 1790500000, blockNumber: 600000001, blockTime: 1791100000 }) } }), expect: { valid: false, levels: L(true, true, false, true, true), codes: ['KEY_REVOKED'] } });
const fwdSeal = S.sealReceipt(K.A, S.sealBody({ sealed_at: '2026-10-06T02:00:00.000Z' }));
const FWD_T = Date.parse('2026-10-06T02:00:00.000Z') / 1000;
const fwdIds = S.idsOf(fwdSeal.signature, `FRACTALAI-x402-served-v1\nx402-witness\n${fwdSeal.content_id}`, fwdSeal.public_key);
V('N-RTE5b-forward-dated-seal', { title: 'x402 seal claims sealed_at two hours AFTER the block that anchors it', source: ['redteam-anchor:RT-E5'], input: { receipt: fwdSeal }, context: synth({ options: { kind: 'x402-seal', check_anchors: true, anchors: [synAnchor(600000002)], rpc: { 'eip155:42161': ['replay://synthetic-arb1'] }, policy: { require: ['integrity', 'authentic', 'trusted', 'time_anchored'] } }, ctx: { rpc_transcript: synT({ ids: fwdIds, observedAt: FWD_T, blockNumber: 600000002, blockTime: FWD_T - 7200 }) } }), expect: { valid: false, levels: L(true, true, true, false, false), codes: ['ANCHOR_FORWARD_DATED'] } });

// ═════════════════════════ Solana anchors (RT-S*) ═════════════════════════
const solRef = { chain: 'solana', cluster: 'devnet', signature: SOL_REC.anchor.signature };
const solT = (mut) => { const t = clone(T('sol-devnet')); mut(t); return t; };
const getTx = (t) => t.find((x) => x.method === 'getTransaction').result;
const solCase = (title, src, transcript, codes, extra = {}) => ({
  title, source: src, input: { receipt: SOL_REC.seal },
  context: realCtx({ options: { check_anchors: true, anchors: [extra.ref ?? solRef], rpc: extra.rpc ?? { 'solana:devnet': ['replay://sol-devnet'] }, policy: { require: ['integrity', 'authentic', 'trusted', 'time_anchored'], allowTestnetAnchors: true }, ...(extra.signers ? { solana_signers: extra.signers } : {}) }, ctx: { rpc_transcript: transcript } }),
  expect: { valid: extra.valid ?? false, levels: extra.levels ?? L(true, true, true, false, false), codes },
});
V('N-RTS2-devnet-rpc-as-mainnet', solCase('Devnet RPC queried as mainnet-beta (genesis hash check)', ['redteam-anchor:RT-S2'], [REF('fixtures/transcripts/sol-devnet.json#transcript')], ['SOL_GENESIS_MISMATCH'], { ref: { ...solRef, cluster: 'mainnet-beta' }, rpc: { 'solana:mainnet-beta': ['replay://sol-devnet'] } }));
V('N-RTS3-blocktime-null', solCase('Finalized tx with blockTime null', ['redteam-anchor:RT-S3'], solT((t) => { getTx(t).blockTime = null; }), ['SOL_NO_BLOCKTIME']));
V('N-RTS4-status-slot-mismatch', solCase('getSignatureStatuses slot differs from getTransaction slot', ['redteam-anchor:RT-S4'], solT((t) => { t.find((x) => x.method === 'getSignatureStatuses').result.value[0].slot += 1; }), ['SOL_STATUS_SLOT']));
V('N-RTS4-status-confirmed', solCase('Status only "confirmed"', ['redteam-anchor:RT-S4'], solT((t) => { t.find((x) => x.method === 'getSignatureStatuses').result.value[0].confirmationStatus = 'confirmed'; }), ['SOL_NOT_FINALIZED']));
V('N-RTS4-cross-rpc-blocktime', solCase('Second RPC reports another blockTime', ['redteam-anchor:RT-S4'], [REF('fixtures/transcripts/sol-devnet.json#transcript'), ...solT((t) => { getTx(t).blockTime += 100; }).map((x) => ({ ...x, url: 'replay://sol-liar' }))], ['RPC_DISAGREEMENT'], { rpc: { 'solana:devnet': ['replay://sol-devnet', 'replay://sol-liar'] } }));
V('N-RTS-tx-failed', solCase('meta.err set', [], solT((t) => { getTx(t).meta.err = { InstructionError: [0, 'Custom'] }; }), ['ANCHOR_TX_FAILED']));
const wireOf = (t) => Buffer.from(getTx(t).transaction[0], 'base64');
V('N-RTS7-truncated-wire', solCase('Truncated transaction bytes', ['redteam-anchor:RT-S7'], solT((t) => { getTx(t).transaction[0] = wireOf(t).subarray(0, wireOf(t).length - 10).toString('base64'); }), ['SOL_TX_MALFORMED']));
V('N-RTS7-trailing-byte', solCase('Trailing byte after the message', ['redteam-anchor:RT-S7'], solT((t) => { getTx(t).transaction[0] = Buffer.concat([wireOf(t), Buffer.from([0])]).toString('base64'); }), ['SOL_TX_MALFORMED']));
V('N-RTS-ed25519-tampered-memo', solCase('Memo byte flipped in the wire: Ed25519 must fail locally (never trust the RPC on who signed)', ['redteam-anchor:RT-S1'], solT((t) => { const w = wireOf(t); w[w.length - 1] ^= 1; getTx(t).transaction[0] = w.toString('base64'); }), ['SOL_ED25519_INVALID']));
V('N-RTS-signer-not-announced', solCase('Real signer not in the (overridden) announced set', ['redteam-anchor:RT-S1'], [REF('fixtures/transcripts/sol-devnet.json#transcript')], ['SOL_SIGNER_NOT_ANNOUNCED'], { signers: ['11111111111111111111111111111112'] }));

// synthetic Solana transactions by a TEST anchor key (announced via the solana_signers override)
const SIG = S.edKey('anchor'), OTHER = S.edKey('other');
const fe62Ids = S.idsOf(FE62.signature, FE62.served_message, FE62.public_key);
const MEMO = S.buildMemo({ ...fe62Ids, observed_at: FE62.emitted_at });
const synSol = (title, src, msg, codes, { signer = SIG, valid = false, levels, tOpts = {} } = {}) => {
  const tx = S.solTx(msg, signer);
  return { title, source: src, input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: realCtx({ options: { check_anchors: true, anchors: [{ chain: 'solana', cluster: 'devnet', signature: tx.signature }], rpc: { 'solana:devnet': ['replay://sol-synthetic'] }, solana_signers: [SIG.b58], policy: { require: ['integrity', 'authentic', 'trusted', 'time_anchored'], allowTestnetAnchors: true } }, ctx: { rpc_transcript: S.solTranscript({ url: 'replay://sol-synthetic', tx, ...tOpts }) } }), expect: { valid, levels: levels ?? L(true, true, true, false, false), codes } };
};
V('P20-solana-synthetic-legacy-control', synSol('Control: canonical one-memo legacy tx by the announced test signer', ['redteam-anchor:RT-S0'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, MEMO)] }), [], { valid: true, levels: L(true, true, true, true, true) }));
V('P21-solana-synthetic-v0-no-lookups', synSol('v0 transaction without lookup tables', ['redteam-anchor:RT-S1b'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, MEMO)], v0: true }), [], { valid: true, levels: L(true, true, true, true, true) }));
V('N-RTS1-other-signer', synSol('Same memo signed by a non-announced key', ['redteam-anchor:RT-S1'], S.solMessage({ payer: OTHER.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, MEMO)] }), ['SOL_SIGNER_NOT_ANNOUNCED'], { signer: OTHER }));
V('N-RTS1-two-memos', synSol('Two memo instructions', ['redteam-anchor:RT-S1'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, MEMO), S.memoIx(1, MEMO.replace('obs=', 'obs=9'))] }), ['SOL_INSTRUCTION_COUNT']));
V('N-RTS1-memo-v1', synSol('Memo v1 program', ['redteam-anchor:RT-S1'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_V1], ixs: [S.memoIx(1, MEMO)] }), ['SOL_NOT_MEMO']));
V('N-RTS1-cpi-other-program', synSol('Memo bytes passed to another program (memo would only exist in a CPI)', ['redteam-anchor:RT-S1'], S.solMessage({ payer: SIG.pub, extraKeys: [S.SYSTEM, S.MEMO_PROGRAM_ID], ixs: [{ prog: 1, accts: [0, 2], data: [...new TextEncoder().encode(MEMO)] }] }), ['SOL_NOT_MEMO']));
V('N-RTS1-durable-nonce', synSol('AdvanceNonceAccount + memo (two instructions)', ['redteam-anchor:RT-S1'], S.solMessage({ payer: SIG.pub, extraKeys: [S.SYSTEM, S.MEMO_PROGRAM_ID], ixs: [{ prog: 1, accts: [0], data: [4, 0, 0, 0] }, S.memoIx(2, MEMO)] }), ['SOL_INSTRUCTION_COUNT']));
V('N-RTS1b-v0-lookup-table', synSol('v0 transaction with an address lookup table', ['redteam-anchor:RT-S1b'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, MEMO)], v0: true, lookups: 1 }), ['SOL_LOOKUP_TABLES']));
const ridHex = fe62Ids.receipt_id;
for (const [n, m] of [['uppercase-rid', MEMO.replace(ridHex, ridHex.toUpperCase())], ['space', MEMO.replace('|ph=', ' |ph=')], ['fullwidth-bar', MEMO.replace('|kid=', '\uff5ckid=')], ['trailing-nul', MEMO + '\u0000'], ['0x-rid', MEMO.replace('rid=', 'rid=0x')], ['forged-obs', MEMO.replace(/obs=\d+$/, 'obs=1700000000')]]) {
  V(`N-RTS1c-memo-${n}`, synSol(`Memo encoding trick: ${n}`, ['redteam-anchor:RT-S1c', 'redteam-anchor:RT-S5'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, m)] }), ['SOL_MEMO_MISMATCH']));
}
V('N-RTS-blocktime-before-signed', synSol('blockTime long before the signed emitted_at (forward-dated receipt)', ['redteam-anchor:RT-E5 (Solana)'], S.solMessage({ payer: SIG.pub, extraKeys: [S.MEMO_PROGRAM_ID], ixs: [S.memoIx(1, MEMO)] }), ['ANCHOR_FORWARD_DATED'], { tOpts: { blockTime: 1780000000 } }));

// ═══════════════ latam-stablecoin-receipt (spec §12): REAL transfers of COPM / BRLA / MXNB, replayed ═══════════════
// Positives: real Transfer logs read by eth_getLogs on 2026-10-08 and recorded (corpus/record-stablecoins.mjs) from
// public RPCs; each receipt is produced by the real issuer (issuer/src/issue.mjs) over the replayed transcript and signed
// by a deterministic TEST key listed (use "stablecoin-receipt") in a TEST directory. Negatives: the same real facts
// altered by a document forger (A1), signed by a compromised/buggy signer (A4), or served by a lying RPC (A6).
{
  const { issueStablecoinReceipt, signTransfer } = await import('../issuer/src/issue.mjs');
  const SC = (n) => read(`./fixtures/stablecoin/${n}.json`);
  const FX = { copm: SC('copm-polygon'), brlaP: SC('brla-polygon'), brlaB: SC('brla-base'), mxnbA: SC('mxnb-arbitrum'), mxnbB: SC('mxnb-base-swap') };
  const SCREF = (n) => REF(`fixtures/stablecoin/${n}.json#transcript`);
  const tsOf = (fx) => Math.floor(Date.parse(fx.recorded_at) / 1000);
  const KS = S.mlKey('stablecoin-issuer'), KX = S.mlKey('x402-only'), KSR = S.mlKey('stablecoin-reserved');
  const keyOf = (k) => ({ secretKey: k.sk, publicKeyB64: k.pk });
  const DS = S.directory([
    { key: KS, use: 'stablecoin-receipt', status: 'active', not_before: 1790000000 },
    { key: KX, use: 'x402-receipt', status: 'active', not_before: 1790000000 },
    { key: KSR, use: 'stablecoin-receipt', status: 'reserved' },
  ], GOV, { epoch: 3, prevRoot: sha256hex('stablecoin-epoch-2') });
  const TRS = S.testRoots(GOV, DS);
  const KIND = 'latam-stablecoin-receipt';
  const REQ = ['integrity', 'authentic', 'trusted', 'onchain'];
  const LS = (i, a, t, o) => ({ ...L(i, a, t), onchain: o });
  const OKS = LS(true, true, true, true);
  const replayOf = (fx) => replayFetch(fx.transcript);

  const issue = async (fx, labels, o = {}) => (await issueStablecoinReceipt({
    chainId: fx.chain_id, txHash: fx.tx_hash, logIndex: fx.log_index, rpcUrls: labels, key: keyOf(o.key ?? KS), now: tsOf(fx),
    deterministic: true, selfVerify: false, fetchImpl: replayOf(fx), reference: o.reference ?? '', requireFinalized: o.requireFinalized ?? true,
  })).receipt;
  const R = {
    copm: await issue(FX.copm, ['replay://polygon', 'replay://polygon-1rpc'], { reference: 'factura:FE-2026-000123' }),
    brlaP: await issue(FX.brlaP, ['replay://polygon']),
    brlaB: await issue(FX.brlaB, ['replay://base']),
    mxnbA: await issue(FX.mxnbA, ['replay://arb1']),
    mxnbB: await issue(FX.mxnbB, ['replay://base']),
  };
  const resign = (base, mut, key = KS) => { const f = { ...base.transfer }; mut(f); return signTransfer(f, keyOf(key), { deterministic: true }); };
  const ctxS = (fx, rpc, o = {}) => ({
    now: tsOf(fx) + 600, roots: TRS, directory: DS,
    options: { kind: KIND, check_onchain: true, rpc, policy: { require: REQ, ...(o.policy || {}) }, ...(o.options || {}) },
    rpc_transcript: o.transcript ?? [SCREF(fx === FX.copm ? 'copm-polygon' : fx === FX.brlaP ? 'brla-polygon' : fx === FX.brlaB ? 'brla-base' : fx === FX.mxnbA ? 'mxnb-arbitrum' : 'mxnb-base-swap')],
  });
  const P137 = { 'eip155:137': ['replay://polygon'] }, P137Q = { 'eip155:137': ['replay://polygon', 'replay://polygon-1rpc'] };
  const B8453 = { 'eip155:8453': ['replay://base'] }, A42161 = { 'eip155:42161': ['replay://arb1'] }, A42161Q = { 'eip155:42161': ['replay://arb1', 'replay://arb1-1rpc'] };
  const mutT = (fx, fn) => { const t = clone(fx.transcript); fn(t); return t; };
  const rcOf = (t, url = null) => t.find((x) => x.method === 'eth_getTransactionReceipt' && (url === null || x.url === url)).result;
  const blkOf = (t, url = null) => t.find((x) => x.method === 'eth_getBlockByNumber' && x.params[0] !== 'finalized' && (url === null || x.url === url));
  const logAt = (t, i, url = null) => rcOf(t, url).logs.find((l) => parseInt(l.logIndex, 16) === i);

  // ── positives (real data) ──
  V('P30-stablecoin-copm-polygon-two-rpcs', { title: 'REAL COPM transfer on Polygon (667,703 COPM), issued by the issuer, re-verified on-chain against two independent public RPCs (quorum 2)', source: ['real:polygon:0x5cd84fa7…420b#2229'], input: { receipt: R.copm }, context: ctxS(FX.copm, P137Q, { policy: { rpcQuorum: 2 } }), expect: { valid: true, levels: OKS, trust_basis: 'override', exit_code: 0 } });
  V('P31-stablecoin-brla-polygon', { title: 'REAL BRLA transfer on Polygon (8.4 BRLA), recomputed from the chain', source: ['real:polygon:0x24f4d154…a387#593'], input: { receipt: R.brlaP }, context: ctxS(FX.brlaP, P137), expect: { valid: true, levels: OKS, trust_basis: 'override' } });
  V('P32-stablecoin-brla-base', { title: 'REAL BRLA transfer on Base (48.52 BRLA), recomputed from the chain', source: ['real:base:0xb0928204…dd1e#1011'], input: { receipt: R.brlaB }, context: ctxS(FX.brlaB, B8453), expect: { valid: true, levels: OKS } });
  V('P33-stablecoin-mxnb-arbitrum', { title: 'REAL MXNB transfer on Arbitrum One (135 MXNB), recomputed from the chain', source: ['real:arbitrum:0x54309433…0f66#3'], input: { receipt: R.mxnbA }, context: ctxS(FX.mxnbA, A42161), expect: { valid: true, levels: OKS } });
  V('P34-stablecoin-mxnb-base-inside-a-swap', { title: 'REAL MXNB leg (log 22) of a multi-token swap on Base — the receipt covers exactly that log', source: ['real:base:0x9963ad6a…d4c8#22'], input: { receipt: R.mxnbB }, context: ctxS(FX.mxnbB, B8453), expect: { valid: true, levels: OKS } });
  V('P35-stablecoin-offline-default-policy', { title: 'Same COPM receipt verified OFFLINE (default policy): integrity + authentic + trusted, on-chain level not evaluated', input: { receipt: R.copm }, context: { now: tsOf(FX.copm) + 600, roots: TRS, directory: DS, options: { kind: KIND } }, expect: { valid: true, levels: LS(true, true, true, null) } });
  V('P36-stablecoin-trusted-keys-override', { title: 'Pinned key set (no directory) + on-chain recomputation', input: { receipt: R.brlaP }, context: { now: tsOf(FX.brlaP) + 600, options: { kind: KIND, trusted_keys: [KS.pk], check_onchain: true, rpc: P137, policy: { require: REQ } }, rpc_transcript: [SCREF('brla-polygon')] }, expect: { valid: true, levels: OKS, trust_basis: 'override' } });
  const mxnbConfirmed = resign(R.mxnbA, (f) => { f.finality = 'confirmed'; });
  V('P37-stablecoin-confirmed-allowed-by-policy', { title: 'Receipt that claims only "confirmed"; second RPC (real 1rpc answer) does not report the block finalized; policy allows unfinalized payments', source: ['real:arbitrum:1rpc finalized tag lags'], input: { receipt: mxnbConfirmed }, context: ctxS(FX.mxnbA, A42161Q, { policy: { rpcQuorum: 2, allowUnfinalizedPayment: true } }), expect: { valid: true, levels: OKS } });

  // ── A1: document forger (no key) ──
  const fwd = (r, m) => { const x = clone(r); m(x); return x; };
  V('N-SC-amount-altered-unsigned-copy', { title: 'Unsigned transfer.amount raised ×10 (what a dashboard reads); signed canonical untouched', input: { receipt: fwd(R.copm, (x) => { x.transfer.amount = x.transfer.amount + '0'; }) }, context: ctxS(FX.copm, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['UNSIGNED_FIELD_MISMATCH'], exit_code: 10 } });
  V('N-SC-amount-as-json-number', { title: 'Unsigned transfer.amount as a JSON number (1e21-style precision loss would compare "equal" as a double)', source: ['spec:§12.2 strings only (A8)'], input: { receipt_text: JSON.stringify(R.mxnbA).replace(`"amount":"${R.mxnbA.transfer.amount}"`, `"amount":${R.mxnbA.transfer.amount}`) }, context: ctxS(FX.mxnbA, A42161), expect: { valid: false, levels: LS(false, false, false, null), codes: ['UNSIGNED_FIELD_MISMATCH'] } });
  const altered = fwd(R.copm, (x) => { x.transfer_canonical = x.transfer_canonical.replace(`amount=${x.transfer.amount}\namount_decimal=${x.transfer.amount_decimal}`, `amount=${x.transfer.amount}0\namount_decimal=${x.transfer.amount_decimal}0`); x.transfer_id = sha256hex(x.transfer_canonical); x.signed_message = `FRACTALAI-stablecoin-receipt-v1\n${x.transfer_id}`; x.transfer.amount += '0'; x.transfer.amount_decimal += '0'; });
  V('N-SC-amount-altered-canonical', { title: 'Signed canonical amount raised ×10 (ids recomputed): the genuine signature does not cover it', input: { receipt: altered }, context: ctxS(FX.copm, P137), expect: { valid: false, levels: LS(true, false, false, null), codes: ['SIGNATURE_INVALID'], exit_code: 11 } });
  V('N-SC-domain-relabelled', { title: 'Receipt relabelled with the x402 served domain', input: { receipt: fwd(R.brlaP, (x) => { x.domain = 'FRACTALAI-x402-served-v1'; }) }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['DOMAIN_MISMATCH'] } });
  V('N-SC-kind-ambiguous-midas-marker', { title: 'Stablecoin receipt carrying a MIDAS `canonical` field', input: { receipt: fwd(R.brlaP, (x) => { x.canonical = 'FRACTALAI-midas-alert-v1'; }) }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['KIND_AMBIGUOUS'] } });
  V('N-SC-midas-alert-cannot-claim-onchain', { title: 'A genuine MIDAS alert under a policy that requires the onchain level', input: { receipt: REF('fixtures/midas-fe62b072.json') }, context: realCtx({ options: { check_onchain: true, policy: { require: ['integrity', 'authentic', 'trusted', 'onchain'] } } }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['ONCHAIN_NOT_APPLICABLE'], exit_code: 15 } });

  // ── registry (integrity, offline) — even a validly signed receipt is refused ──
  V('N-SC-fake-token-same-symbol', { title: 'Receipt (validly signed) for a look-alike contract with symbol COPM / 18 decimals', input: { receipt: resign(R.copm, (f) => { f.token = '0x00000000000000000000000000000000c0b1dead'; }) }, context: ctxS(FX.copm, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['TOKEN_NOT_PINNED'] } });
  V('N-SC-wrong-chain-in-receipt', { title: 'Receipt claims chain 8453 (Base) for the Polygon COPM address', input: { receipt: resign(R.copm, (f) => { f.chain_id = '8453'; }) }, context: ctxS(FX.copm, B8453), expect: { valid: false, levels: LS(false, false, false, null), codes: ['TOKEN_NOT_PINNED'] } });
  V('N-SC-pinned-token-wrong-symbol', { title: 'Real COPM address labelled COPW', input: { receipt: resign(R.copm, (f) => { f.token_symbol = 'COPW'; }) }, context: ctxS(FX.copm, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['TOKEN_METADATA_MISMATCH'] } });
  V('N-SC-amount-decimal-mismatch', { title: 'amount_decimal does not render amount at the pinned decimals', input: { receipt: resign(R.mxnbA, (f) => { f.amount_decimal = '135000000'; }) }, context: ctxS(FX.mxnbA, A42161), expect: { valid: false, levels: LS(false, false, false, null), codes: ['AMOUNT_FORMAT_MISMATCH'] } });
  V('N-SC-mint-is-not-a-payment', { title: 'Receipt for a mint (from = zero address)', input: { receipt: resign(R.brlaP, (f) => { f.from = '0x' + '0'.repeat(40); }) }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['PAYMENT_NOT_A_TRANSFER'] } });
  const rawSign = (canonical, key = KS) => { const id = sha256hex(canonical); const m = `FRACTALAI-stablecoin-receipt-v1\n${id}`; return { algorithm: 'ml-dsa-65', domain: 'FRACTALAI-stablecoin-receipt-v1', transfer_id: id, transfer_canonical: canonical, signed_message: m, public_key: key.pk, signature: key.sign(m) }; };
  V('N-SC-issued-before-block', { title: 'issued_at earlier than the block that carries the transfer (raw canonical signed by a buggy signer)', input: { receipt: rawSign(R.brlaP.transfer_canonical.replace(/issued_at=\d+/, `issued_at=${Number(R.brlaP.transfer.block_timestamp) - 1}`)) }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['CANONICAL_MALFORMED'] } });
  V('N-SC-extra-field-in-canonical', { title: 'Canonical with an extra line (memo=…) appended and signed', input: { receipt: rawSign(R.brlaP.transfer_canonical + '\nmemo=x') }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(false, false, false, null), codes: ['CANONICAL_MALFORMED'] } });

  // ── trust (key use / directory) ──
  V('N-SC-x402-key-cannot-sign-payments', { title: 'Same facts signed by an active key whose use is x402-receipt', input: { receipt: resign(R.brlaP, () => {}, KX) }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(true, true, false, true), codes: ['KEY_USE_MISMATCH'], exit_code: 12 } });
  V('N-SC-reserved-key', { title: 'Signed by a reserved (never activated) stablecoin key', input: { receipt: resign(R.brlaP, () => {}, KSR) }, context: ctxS(FX.brlaP, P137), expect: { valid: false, levels: LS(true, true, false, true), codes: ['KEY_STATUS_RESERVED'] } });
  V('N-SC-production-directory-has-no-stablecoin-key', { title: 'Real epoch-3 production directory (pinned roots): no key with use stablecoin-receipt is published yet', input: { receipt: R.brlaP }, context: { now: tsOf(FX.brlaP) + 600, directory: REF('fixtures/directory-epoch3.json'), options: { kind: KIND } }, expect: { valid: false, levels: LS(true, true, false, null), trust_basis: 'pinned-root', codes: ['KEY_NOT_LISTED'] } });
  V('N-SC-signed-time-in-future', { title: 'issued_at a day after verification time', input: { receipt: resign(R.brlaP, (f) => { f.issued_at = String(tsOf(FX.brlaP) + 86400 * 2); }) }, context: { now: tsOf(FX.brlaP) + 600, roots: TRS, directory: DS, options: { kind: KIND } }, expect: { valid: false, levels: LS(true, true, false, null), codes: ['SIGNED_TIME_IN_FUTURE'] } });

  // ── A4: compromised / buggy signer — the chain contradicts the signature ──
  V('N-SC-compromised-signer-inflates-amount', { title: 'Valid key signs the real tx with amount ×10: authentic and trusted, refused by the chain', input: { receipt: resign(R.copm, (f) => { f.amount += '0'; f.amount_decimal += '0'; }) }, context: ctxS(FX.copm, P137), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_AMOUNT_MISMATCH'], exit_code: 15 } });
  V('N-SC-compromised-signer-swaps-parties', { title: 'Valid key signs the real tx with from/to swapped', input: { receipt: resign(R.brlaB, (f) => { [f.from, f.to] = [f.to, f.from]; }) }, context: ctxS(FX.brlaB, B8453), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_PARTY_MISMATCH'] } });
  V('N-SC-compromised-signer-block-time', { title: 'Signed block_timestamp one second later than the header', input: { receipt: resign(R.brlaB, (f) => { f.block_timestamp = String(Number(f.block_timestamp) + 1); }) }, context: ctxS(FX.brlaB, B8453), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_TIME_MISMATCH'] } });
  V('N-SC-confirmations-overclaimed', { title: 'Signer claims 10,000,000 confirmations', input: { receipt: resign(R.brlaB, (f) => { f.confirmations = '10000000'; }) }, context: ctxS(FX.brlaB, B8453), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_CONFIRMATIONS'] } });
  const usdc = logAt(FX.mxnbB.transcript, 23);
  V('N-SC-log-of-another-contract', { title: 'REAL swap tx: receipt says MXNB at log 23, which is a USDC Transfer (another contract)', source: ['real:base:0x9963ad6a…d4c8#23'], input: { receipt: resign(R.mxnbB, (f) => { f.log_index = '23'; f.from = '0x' + usdc.topics[1].slice(26); f.to = '0x' + usdc.topics[2].slice(26); f.amount = BigInt(usdc.data).toString(); f.amount_decimal = formatUnits(BigInt(usdc.data).toString(), 6); }) }, context: ctxS(FX.mxnbB, B8453), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_LOG_WRONG_CONTRACT'] } });
  V('N-SC-approval-is-not-a-transfer', { title: 'REAL swap tx: log 25 is an MXNB Approval event, not a Transfer', source: ['real:base:0x9963ad6a…d4c8#25'], input: { receipt: resign(R.mxnbB, (f) => { f.log_index = '25'; }) }, context: ctxS(FX.mxnbB, B8453), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_LOG_NOT_TRANSFER'] } });
  V('N-SC-log-index-absent', { title: 'log_index not present in the transaction', input: { receipt: resign(R.mxnbA, (f) => { f.log_index = '999'; }) }, context: ctxS(FX.mxnbA, A42161), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_LOG_NOT_FOUND'] } });
  V('N-SC-claimed-finality-not-reported', { title: 'REAL: receipt claims "finalized"; the second RPC (1rpc) does not report the block finalized → fail closed', source: ['real:arbitrum:1rpc finalized tag lags'], input: { receipt: R.mxnbA }, context: ctxS(FX.mxnbA, A42161Q, { policy: { rpcQuorum: 2 } }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_NOT_FINALIZED'] } });
  V('N-SC-unfinalized-default-policy', { title: 'Receipt claiming only "confirmed", block not finalized on every RPC, default policy requires finality', input: { receipt: mxnbConfirmed }, context: ctxS(FX.mxnbA, A42161Q, { policy: { rpcQuorum: 2 } }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_NOT_FINALIZED'] } });

  // ── A6: chain / RPC says otherwise (reorg, revert, wrong network, disagreement) ──
  V('N-SC-tx-reverted', { title: 'The transaction reverted (status 0x0): no transfer happened', input: { receipt: R.brlaP }, context: ctxS(FX.brlaP, P137, { transcript: mutT(FX.brlaP, (t) => { rcOf(t).status = '0x0'; }) }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_TX_REVERTED'] } });
  V('N-SC-tx-not-found', { title: 'The RPC does not know the transaction (dropped / other network)', input: { receipt: R.brlaP }, context: ctxS(FX.brlaP, P137, { transcript: mutT(FX.brlaP, (t) => { t.find((x) => x.method === 'eth_getTransactionReceipt').result = null; }) }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_TX_NOT_FOUND'] } });
  V('N-SC-wrong-chain-rpc', { title: 'Polygon receipt checked against an RPC that serves Base (real Base eth_chainId)', input: { receipt: R.copm }, context: ctxS(FX.copm, { 'eip155:137': ['replay://base'] }, { transcript: [SCREF('brla-base')] }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_WRONG_CHAIN'] } });
  const reorgHeader = mutT(FX.mxnbA, (t) => { blkOf(t, 'replay://arb1').result.hash = '0x' + sha256hex('reorg/mxnb').slice(0, 64); });
  V('N-SC-reorg-block-not-canonical', { title: 'Simulated reorg: the canonical header at block_number has another hash than the receipt\'s block', input: { receipt: R.mxnbA }, context: ctxS(FX.mxnbA, A42161, { transcript: reorgHeader }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_REORGED'] } });
  const NEWH = '0x' + sha256hex('reorg/new-block').slice(0, 64);
  const reincl = mutT(FX.mxnbA, (t) => { const rc = rcOf(t, 'replay://arb1'); rc.blockHash = NEWH; for (const l of rc.logs) l.blockHash = NEWH; blkOf(t, 'replay://arb1').result.hash = NEWH; });
  V('N-SC-reorg-reincluded-same-height', { title: 'Simulated reorg: the tx was re-included at the same height in a different block (signed block_hash no longer canonical)', input: { receipt: R.mxnbA }, context: ctxS(FX.mxnbA, A42161, { transcript: reincl }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_REORGED'] } });
  const moved = mutT(FX.mxnbA, (t) => { const rc = rcOf(t, 'replay://arb1'); const n = '0x' + (parseInt(rc.blockNumber, 16) + 1).toString(16); rc.blockNumber = n; for (const l of rc.logs) l.blockNumber = n; const b = blkOf(t, 'replay://arb1'); b.params = [n, false]; b.result.number = n; });
  V('N-SC-reorg-moved-to-next-block', { title: 'Simulated reorg: the tx now lives in block_number + 1', input: { receipt: R.mxnbA }, context: ctxS(FX.mxnbA, A42161, { transcript: moved }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_BLOCK_MISMATCH'] } });
  V('N-SC-log-removed', { title: 'The Transfer log is flagged removed (reorg in progress)', input: { receipt: R.mxnbA }, context: ctxS(FX.mxnbA, A42161, { transcript: mutT(FX.mxnbA, (t) => { logAt(t, 3, 'replay://arb1').removed = true; }) }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_LOG_REMOVED'] } });
  V('N-SC-token-symbol-changed-onchain', { title: 'Upgradeable proxy now answers symbol() = "BRLX": live metadata differs from the signed one', input: { receipt: R.brlaP }, context: ctxS(FX.brlaP, P137, { transcript: mutT(FX.brlaP, (t) => { const c = t.find((x) => x.method === 'eth_call' && x.params[0].data === '0x95d89b41'); c.result = '0x' + (32).toString(16).padStart(64, '0') + (4).toString(16).padStart(64, '0') + Buffer.from('BRLX').toString('hex').padEnd(64, '0'); }) }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['PAYMENT_TOKEN_METADATA'] } });
  const lying = [...FX.copm.transcript.filter((x) => x.url === 'replay://polygon'), ...mutT(FX.copm, (t) => { logAt(t, 2229, 'replay://polygon-1rpc').data = '0x' + (BigInt(logAt(t, 2229, 'replay://polygon-1rpc').data) * 10n).toString(16).padStart(64, '0'); }).filter((x) => x.url === 'replay://polygon-1rpc')];
  V('N-SC-cross-rpc-disagreement', { title: 'Second RPC reports a different amount for the same log', input: { receipt: R.copm }, context: ctxS(FX.copm, P137Q, { transcript: lying }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['RPC_DISAGREEMENT'] } });
  V('N-SC-quorum-not-met', { title: 'Policy requires 2 RPCs, one configured', input: { receipt: R.copm }, context: ctxS(FX.copm, P137, { policy: { rpcQuorum: 2 } }), expect: { valid: false, levels: LS(true, true, true, false), codes: ['RPC_QUORUM'] } });
}

// ── manifest: id → sha256 of the vector file (the runner refuses a corpus that does not match) ──
const files = readdirSync(OUT).filter((f) => f.endsWith('.json')).sort();
const manifest = { format: 'fractalai.trust-corpus/1', kernel_spec: '2.0.0', count: files.length, vectors: Object.fromEntries(files.map((f) => [f.replace(/\.json$/, ''), sha256hex(readFileSync(new URL(f, OUT)))])) };
writeFileSync(here('./manifest.json'), JSON.stringify(manifest, null, 1) + '\n');
console.log(`wrote ${files.length} vectors (${files.filter((f) => f.startsWith('P')).length} positive, ${files.filter((f) => f.startsWith('N')).length} negative)`);
