/**
 * verify-anchor.mjs — REAL ML-DSA-65 signatures (fresh keypair), a mocked Arbitrum JSON-RPC that
 * answers eth_chainId / eth_getTransactionReceipt / eth_getLogs / eth_blockNumber the way a node does,
 * and the exact event encoding PQCReceiptAnchor emits. Fail-closed on every tampered dimension.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeypair } from '../src/self-attest.mjs';
import { signSeal, NOTARY_DOMAIN } from '../src/witness-core.mjs';
import { verifyAnchoredSeal, deriveAnchorIds, trustedKeysFromDirectory, RECEIPT_ANCHORED_TOPIC, ANCHOR_SCHEME } from '../src/verify-anchor.mjs';

const CONTRACT = '0x1111111111111111111111111111111111111111';
const ANCHORER = '0x39db643192c0e81f2bc13883ad8c1a0e4060bf63';
const TX = '0x' + 'ab'.repeat(32);
const CHAIN = 421614;
const BLOCK = 123456;
const ANCHORED_AT = 1_759_500_000;
const OBSERVED_AT = ANCHORED_AT - 5;

const kp = generateKeypair();
const pkB64 = Buffer.from(kp.publicKey).toString('base64');
const body = {
  schema: 'fractalai.x402-settlement-seal/0.1', resource: 'https://example.com/api/x402/thing', scheme: 'exact',
  network: 'eip155:8453', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: '0xC13789e82661635d9Cea38a53A0390CF9939ef4f',
  amount: '20000', payer: '0x9ddd0b192480d9f0a2eB0147cD56f67c2E249B06', transaction: '0x' + '11'.repeat(32), success: true,
  response_sha256: null, sealed_at: '2026-10-03T00:00:00.000Z',
};
const seal0 = signSeal(body, { domain: NOTARY_DOMAIN, secretKey: kp.secretKey, publicKey: kp.publicKey });
const ids = deriveAnchorIds(seal0);

const hex32 = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');
const eventData = ({ observedAt = OBSERVED_AT, anchoredBy = ANCHORER, anchoredAt = ANCHORED_AT } = {}) =>
  '0x' + BigInt(observedAt).toString(16).padStart(64, '0') + anchoredBy.slice(2).toLowerCase().padStart(64, '0') + BigInt(anchoredAt).toString(16).padStart(64, '0');
const makeLog = (o = {}) => ({
  address: CONTRACT, topics: [RECEIPT_ANCHORED_TOPIC, o.receiptId ?? ids.receipt_id, o.payloadHash ?? ids.payload_hash, o.kid ?? ids.kid],
  data: eventData(o), logIndex: '0x' + (o.logIndex ?? 7).toString(16), blockNumber: '0x' + BLOCK.toString(16), transactionHash: TX,
});

function mockRpc({ chainId = CHAIN, receipt, logs, head = BLOCK + 3 } = {}) {
  const calls = [];
  const fetchImpl = async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    calls.push(method);
    const reply = (result) => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) });
    if (method === 'eth_chainId') return reply('0x' + chainId.toString(16));
    if (method === 'eth_blockNumber') return reply('0x' + head.toString(16));
    if (method === 'eth_getTransactionReceipt') return reply(receipt === undefined ? { status: '0x1', blockNumber: '0x' + BLOCK.toString(16), logs: [makeLog()] } : receipt);
    if (method === 'eth_getLogs') {
      assert.equal(params[0].address, CONTRACT.toLowerCase());
      assert.deepEqual(params[0].topics, [RECEIPT_ANCHORED_TOPIC, ids.receipt_id]);
      return reply(logs === undefined ? [makeLog()] : logs);
    }
    throw new Error(`unexpected rpc ${method}`);
  };
  return { fetchImpl, calls };
}

const anchor = { scheme: ANCHOR_SCHEME, chain_id: CHAIN, contract: CONTRACT, tx_hash: TX, log_index: 7, block_number: BLOCK, receipt_id: ids.receipt_id, payload_hash: ids.payload_hash, kid: ids.kid };
const sealWithAnchor = { ...seal0, anchor };

test('deriveAnchorIds: sha256(signature) / sha256(domain\\ncontent_id) / sha256(pubkey_b64)[:16] left-aligned', () => {
  assert.equal(ids.receipt_id, '0x' + createHash('sha256').update(Buffer.from(seal0.signature, 'base64')).digest('hex'));
  assert.equal(ids.payload_hash, '0x' + createHash('sha256').update(`${NOTARY_DOMAIN}\n${seal0.content_id}`, 'utf8').digest('hex'));
  assert.equal(ids.kid, '0x' + createHash('sha256').update(pkB64).digest('hex').slice(0, 16) + '0'.repeat(48));
  assert.throws(() => deriveAnchorIds({ ...seal0, signature: Buffer.alloc(10).toString('base64') }), /3309/);
});

test('happy path via tx_hash + log_index: signature verifies, key pinned, on-chain payloadHash/kid match → valid', async () => {
  const { fetchImpl, calls } = mockRpc();
  const r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.signature_valid, true);
  assert.equal(r.key_trusted, true);
  assert.equal(r.anchor_valid, true);
  assert.equal(r.mode, 'notary');
  assert.equal(r.chain_id, CHAIN);
  assert.equal(r.block_number, BLOCK);
  assert.equal(r.anchored_at, ANCHORED_AT);
  assert.equal(r.anchored_by, ANCHORER);
  assert.equal(r.tx_hash, TX);
  assert.deepEqual(calls, ['eth_chainId', 'eth_getTransactionReceipt', 'eth_blockNumber']);
});

test('happy path via eth_getLogs when the anchor reference has no tx_hash (receiptId topic lookup)', async () => {
  const { fetchImpl, calls } = mockRpc();
  const r = await verifyAnchoredSeal({ ...seal0, anchor: { chain_id: CHAIN, contract: CONTRACT } }, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.tx_hash, TX);
  assert.deepEqual(calls, ['eth_chainId', 'eth_getLogs', 'eth_blockNumber']);
});

test('no key pin → valid but key_trusted null and the reason says identity is NOT authenticated', async () => {
  const r = await verifyAnchoredSeal(sealWithAnchor, { fetchImpl: mockRpc().fetchImpl });
  assert.equal(r.valid, true);
  assert.equal(r.key_trusted, null);
  assert.match(r.reason, /NOT authenticated/);
});

test('fail-closed: signature from an untrusted key is rejected BEFORE any RPC call', async () => {
  const other = generateKeypair();
  const { fetchImpl, calls } = mockRpc();
  const r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [Buffer.from(other.publicKey).toString('base64')], fetchImpl });
  assert.equal(r.valid, false);
  assert.equal(r.signature_valid, true);
  assert.equal(r.key_trusted, false);
  assert.match(r.reason, /key not trusted/);
  assert.deepEqual(calls, []);
});

test('fail-closed: tampered body (content_id mismatch) is rejected offline', async () => {
  const tampered = { ...sealWithAnchor, body: { ...body, amount: '1' } };
  const { fetchImpl, calls } = mockRpc();
  const r = await verifyAnchoredSeal(tampered, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, false);
  assert.match(r.reason, /content_id mismatch/);
  assert.deepEqual(calls, []);
});

test('fail-closed: on-chain payloadHash differs (someone anchored other bytes under this receiptId)', async () => {
  const { fetchImpl } = mockRpc({ receipt: { status: '0x1', blockNumber: hex32(BLOCK), logs: [makeLog({ payloadHash: '0x' + 'cc'.repeat(32) })] } });
  const r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, false);
  assert.match(r.reason, /payloadHash/);
});

test('fail-closed: on-chain kid differs', async () => {
  const { fetchImpl } = mockRpc({ receipt: { status: '0x1', blockNumber: hex32(BLOCK), logs: [makeLog({ kid: '0x' + 'dd'.repeat(32) })] } });
  const r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, false);
  assert.match(r.reason, /kid/);
});

test('fail-closed: wrong chain id from the RPC', async () => {
  const { fetchImpl } = mockRpc({ chainId: 42161 });
  const r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, false);
  assert.match(r.reason, /chain id 42161 != anchor.chain_id 421614/);
});

test('fail-closed: tx not found / reverted / no matching log at log_index', async () => {
  let r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc({ receipt: null }).fetchImpl });
  assert.match(r.reason, /not found/);
  r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc({ receipt: { status: '0x0', logs: [] } }).fetchImpl });
  assert.match(r.reason, /reverted/);
  r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc({ receipt: { status: '0x1', blockNumber: hex32(BLOCK), logs: [makeLog({ logIndex: 8 })] } }).fetchImpl });
  assert.match(r.reason, /log_index 7/);
  assert.equal(r.valid, false);
});

test('fail-closed: anchor reference whose receipt_id does not match sha256(signature) is rejected without RPC', async () => {
  const { fetchImpl, calls } = mockRpc();
  const r = await verifyAnchoredSeal({ ...seal0, anchor: { ...anchor, receipt_id: '0x' + '00'.repeat(31) + '01' } }, { trustedPublicKeysB64: [pkB64], fetchImpl });
  assert.equal(r.valid, false);
  assert.match(r.reason, /receipt_id/);
  assert.deepEqual(calls, []);
});

test('fail-closed: pinned anchorer mismatch, and insufficient confirmations', async () => {
  let r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc().fetchImpl, expectedAnchoredBy: '0x' + '99'.repeat(20) });
  assert.equal(r.valid, false);
  assert.match(r.reason, /anchoredBy/);
  r = await verifyAnchoredSeal(sealWithAnchor, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc({ head: BLOCK }).fetchImpl, minConfirmations: 5 });
  assert.equal(r.valid, false);
  assert.match(r.reason, /confirmations/);
});

test('eth_getLogs path refuses duplicates (write-once invariant) and reports "no event"', async () => {
  let r = await verifyAnchoredSeal({ ...seal0, anchor: { chain_id: CHAIN, contract: CONTRACT } }, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc({ logs: [] }).fetchImpl });
  assert.match(r.reason, /no ReceiptAnchored event/);
  r = await verifyAnchoredSeal({ ...seal0, anchor: { chain_id: CHAIN, contract: CONTRACT } }, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc({ logs: [makeLog(), makeLog()] }).fetchImpl });
  assert.match(r.reason, /multiple/);
});

test('a valid seal WITHOUT an anchor is reported honestly: signature ok, anchor not valid', async () => {
  const r = await verifyAnchoredSeal(seal0, { trustedPublicKeysB64: [pkB64], fetchImpl: mockRpc().fetchImpl });
  assert.equal(r.valid, false);
  assert.equal(r.signature_valid, true);
  assert.equal(r.anchor_valid, false);
  assert.match(r.reason, /no anchor reference/);
});

test('trustedKeysFromDirectory: active + retiring (before not_after) + legacy; never revoked/reserved/expired', () => {
  const now = 1_759_500_000;
  const dir = { keys: [
    { kid: 'a', public_key_b64: 'A' },                                             // epoch-1 legacy shape
    { kid: 'b', public_key_b64: 'B', status: 'active', not_after: null },
    { kid: 'c', public_key_b64: 'C', status: 'retiring', not_after: now + 10 },
    { kid: 'd', public_key_b64: 'D', status: 'retiring', not_after: now - 10 },     // expired
    { kid: 'e', public_key_b64: 'E', status: 'revoked' },
    { kid: 'f', public_key_b64: 'F', status: 'reserved', not_before: null },
  ] };
  assert.deepEqual(trustedKeysFromDirectory(dir, now), ['A', 'B', 'C']);
  assert.deepEqual(trustedKeysFromDirectory({}), []);
});
