/**
 * verify-anchor (compatibility layer over Trust Kernel v2) — offline, real ML-DSA-65, mocked JSON-RPC that
 * answers like a node for the PINNED Arbitrum One deployment (address + real runtime bytecode).
 * Migrated 2026-10-07: the old suite trusted the contract named by the seal, accepted "valid" without a key
 * pin and read the time from event data; these tests assert the kernel semantics instead.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKeypair } from '../src/self-attest.mjs';
import { signSeal, NOTARY_DOMAIN, verifySeal } from '../src/witness-core.mjs';
import { verifyAnchoredSeal, deriveAnchorIds, trustedKeysFromDirectory, RECEIPT_ANCHORED_TOPIC, KNOWN_DEPLOYMENTS } from '../src/verify-anchor.mjs';

const RUNTIME = JSON.parse(readFileSync(new URL('../../corpus/fixtures/transcripts/arc-tx.json', import.meta.url), 'utf8')).transcript.find((t) => t.method === 'eth_getCode').result;
const CHAIN = 42161;
const CONTRACT = KNOWN_DEPLOYMENTS[CHAIN].address;
const BLOCK = 600_000_000;
const SEALED_AT = 1_790_000_000;
const ANCHORED_AT = SEALED_AT + 30;
const BLOCK_HASH = '0x' + 'bb'.repeat(32);
const TX = '0x' + 'ab'.repeat(32);
const ANCHORER = '0xc13789e82661635d9cea38a53a0390cf9939ef4f';
const NOW = 1_791_400_000;

const kp = generateKeypair();
const pkB64 = Buffer.from(kp.publicKey).toString('base64');
const body = { schema: 'fractalai.x402-settlement-seal/0.1', resource: '/api/x402/thing', amount: '20000', payer: '0x9ddd0b192480d9f0a2eb0147cd56f67c2e249b06', transaction: '0x' + '11'.repeat(32), success: true, response_sha256: null, sealed_at: new Date(SEALED_AT * 1000).toISOString() };
const seal0 = signSeal(body, { domain: NOTARY_DOMAIN, secretKey: kp.secretKey, publicKey: kp.publicKey });
const ids = deriveAnchorIds(seal0);
const hex = (n) => '0x' + BigInt(n).toString(16);
const pad = (h) => h.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const makeLog = (o = {}) => ({
  address: CONTRACT, topics: [RECEIPT_ANCHORED_TOPIC, ids.receipt_id, o.payloadHash ?? ids.payload_hash, o.kid ?? ids.kid],
  data: '0x' + pad(hex(o.observedAt ?? SEALED_AT)) + pad(o.anchoredBy ?? ANCHORER) + pad(hex(o.anchoredAt ?? ANCHORED_AT)),
  blockNumber: hex(BLOCK), blockHash: o.blockHash ?? BLOCK_HASH, transactionHash: TX, logIndex: hex(o.logIndex ?? 7), removed: o.removed ?? false,
});
function mockRpc({ chainId = CHAIN, code = RUNTIME, receipt, logs, head = BLOCK + 3, finalized = BLOCK, blockTs = ANCHORED_AT } = {}) {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const { id, method, params } = JSON.parse(init.body);
    calls.push(method);
    const reply = (result) => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify({ jsonrpc: '2.0', id, result }) });
    switch (method) {
      case 'eth_chainId': return reply(hex(chainId));
      case 'eth_getCode': return reply(params[0] === CONTRACT ? code : '0x');
      case 'eth_blockNumber': return reply(hex(head));
      case 'eth_getBlockByNumber': return reply(params[0] === 'finalized' ? { number: hex(finalized) } : { number: params[0], hash: BLOCK_HASH, timestamp: hex(blockTs) });
      case 'eth_getTransactionReceipt': return reply(receipt === undefined ? { status: '0x1', blockNumber: hex(BLOCK), logs: [makeLog()] } : receipt);
      case 'eth_getLogs': return reply(logs ?? [makeLog()]);
      default: throw new Error(`unexpected ${method}`);
    }
  };
  return { fetchImpl, calls };
}
const anchor = { chain_id: CHAIN, tx_hash: TX, log_index: 7 };
const sealWithAnchor = { ...seal0, anchor };
const run = (s, o = {}) => verifyAnchoredSeal(s, { trustedPublicKeysB64: [pkB64], now: NOW, fetchImpl: mockRpc().fetchImpl, ...o });

test('deriveAnchorIds: sha256(signature) / sha256(domain\\ncontent_id) / sha256(pubkey_b64)[:16] left-aligned', () => {
  assert.equal(ids.receipt_id, '0x' + createHash('sha256').update(Buffer.from(seal0.signature, 'base64')).digest('hex'));
  assert.equal(ids.payload_hash, '0x' + createHash('sha256').update(`${NOTARY_DOMAIN}\n${seal0.content_id}`, 'utf8').digest('hex'));
  assert.equal(ids.kid, '0x' + createHash('sha256').update(pkB64).digest('hex').slice(0, 16) + '0'.repeat(48));
});

test('happy path (tx hash): pinned contract + code hash, header time, observedAt == signed time, finalized', async () => {
  const { fetchImpl, calls } = mockRpc();
  const r = await run(sealWithAnchor, { fetchImpl, requireFinalized: true });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.key_trusted, true);
  assert.equal(r.anchor_valid, true);
  assert.equal(r.mode, 'notary');
  assert.equal(r.anchored_at, ANCHORED_AT);
  assert.equal(r.observed_at, SEALED_AT);
  assert.equal(r.contract_known, true);
  assert.equal(r.finalized, true);
  assert.deepEqual(calls, ['eth_chainId', 'eth_getCode', 'eth_getTransactionReceipt', 'eth_getBlockByNumber', 'eth_blockNumber', 'eth_getBlockByNumber']);
});

test('happy path (eth_getLogs, block hint)', async () => {
  const { fetchImpl, calls } = mockRpc();
  const r = await run({ ...seal0, anchor: { chain_id: CHAIN, block_number: BLOCK } }, { fetchImpl });
  assert.equal(r.valid, true, r.reason);
  assert.ok(calls.includes('eth_getLogs'));
});

test('no trust source → NOT valid (a valid signature from an unknown key is not trust)', async () => {
  const r = await verifyAnchoredSeal(sealWithAnchor, { now: NOW, fetchImpl: mockRpc().fetchImpl });
  assert.equal(r.valid, false);
  assert.equal(r.key_trusted, null);
  assert.equal(r.anchor_valid, true, 'the anchor itself still verifies');
});

test('untrusted key → not valid; tampered body → refused before any RPC call', async () => {
  const other = Buffer.from(generateKeypair().publicKey).toString('base64');
  let r = await run(sealWithAnchor, { trustedPublicKeysB64: [other] });
  assert.equal(r.valid, false);
  assert.equal(r.key_trusted, false);
  const { fetchImpl, calls } = mockRpc();
  r = await run({ ...sealWithAnchor, body: { ...body, amount: '1' } }, { fetchImpl });
  assert.equal(r.valid, false);
  assert.match(r.reason, /CONTENT_ID_MISMATCH/);
  assert.deepEqual(calls, []);
});

test('the contract named by the seal is never trusted: unpinned address refused', async () => {
  const r = await run({ ...seal0, anchor: { ...anchor, contract: '0x' + 'ee'.repeat(20) } });
  assert.equal(r.valid, false);
  assert.match(r.reason, /ANCHOR_CONTRACT_NOT_PINNED/);
});

test('code hash, squatting, kid, header time, observedAt, blockHash, removed, chain id, confirmations', async () => {
  const cases = [
    [{ code: '0x6080604052' }, /ANCHOR_CODEHASH_MISMATCH/],
    [{ receipt: { status: '0x1', logs: [makeLog({ payloadHash: '0x' + 'cc'.repeat(32) })] } }, /ANCHOR_SQUATTED/],
    [{ receipt: { status: '0x1', logs: [makeLog({ kid: '0x' + 'dd'.repeat(32) })] } }, /ANCHOR_KID_MISMATCH/],
    [{ blockTs: ANCHORED_AT + 1 }, /ANCHOR_TIME_MISMATCH/],
    [{ receipt: { status: '0x1', logs: [makeLog({ observedAt: 1 })] } }, /ANCHOR_OBSERVED_AT_MISMATCH/],
    [{ receipt: { status: '0x1', logs: [makeLog({ blockHash: '0x' + '01'.repeat(32) })] } }, /ANCHOR_BLOCK_MISMATCH/],
    [{ receipt: { status: '0x1', logs: [makeLog({ removed: true })] } }, /ANCHOR_LOG_REMOVED/],
    [{ chainId: 5042 }, /ANCHOR_WRONG_CHAIN/],
    [{ receipt: null }, /ANCHOR_NOT_FOUND/],
    [{ receipt: { status: '0x0', logs: [] } }, /ANCHOR_TX_FAILED/],
  ];
  for (const [o, re] of cases) {
    const r = await run(sealWithAnchor, { fetchImpl: mockRpc(o).fetchImpl });
    assert.equal(r.valid, false, JSON.stringify(o));
    assert.match(r.reason, re);
  }
  const r = await run(sealWithAnchor, { fetchImpl: mockRpc({ head: BLOCK }).fetchImpl, minConfirmations: 5 });
  assert.match(r.reason, /ANCHOR_CONFIRMATIONS/);
  const f = await run(sealWithAnchor, { fetchImpl: mockRpc({ finalized: BLOCK - 1 }).fetchImpl, requireFinalized: true });
  assert.equal(f.valid, false);
  assert.match(f.reason, /NOT_FINALIZED/);
});

test('expectedAnchoredBy is checked against the consensus fact', async () => {
  const r = await run(sealWithAnchor, { expectedAnchoredBy: '0x' + '99'.repeat(20) });
  assert.equal(r.valid, false);
  assert.match(r.reason, /anchoredBy/);
});

test('a seal WITHOUT an anchor is reported honestly', async () => {
  const r = await run(seal0);
  assert.equal(r.valid, false);
  assert.equal(r.signature_valid, true);
  assert.equal(r.anchor_valid, false);
  assert.match(r.reason, /NO_ANCHOR/);
});

test('trustedKeysFromDirectory: only a directory verified against the PINNED roots yields keys', () => {
  const real = JSON.parse(readFileSync(new URL('../../corpus/fixtures/directory-epoch3.json', import.meta.url), 'utf8'));
  const keys = trustedKeysFromDirectory(real, NOW);
  assert.equal(keys.length, 1, 'only the active key is usable "now" without a signed time');
  assert.deepEqual(trustedKeysFromDirectory({ keys: [{ public_key_b64: 'A' }] }, NOW), []);
  assert.deepEqual(trustedKeysFromDirectory({}), []);
});

test('verifySeal (sync, offline): valid only with a trust source; mode from the fixed seal domains', () => {
  assert.equal(verifySeal(seal0, { trustedPublicKeysB64: [pkB64], now: NOW }).valid, true);
  const r = verifySeal(seal0, { now: NOW });
  assert.equal(r.valid, false);
  assert.equal(r.keyTrusted, null);
  assert.equal(r.signatureValid, true);
});
