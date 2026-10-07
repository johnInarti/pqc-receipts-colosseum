/**
 * solana-anchor — the REAL public MIDAS receipt fe62b072… (ML-DSA-65, production key), REAL Ed25519
 * transactions built and signed with the same code that anchors on devnet/mainnet, and a mocked Solana
 * JSON-RPC answering getTransaction / getSignatureStatuses the way a node does. Fail-closed everywhere.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, createHash } from 'node:crypto';
import {
  verifySolanaAnchor, buildMemo, deriveAnchorIds, sealFromReceipt, buildMemoMessage, signTransaction,
  parseTransaction, b58encode, b58decode, keypairFromSolanaJson, MEMO_PROGRAM_ID, ANCHOR_SCHEME,
} from '../src/solana-anchor.mjs';

const evm = JSON.parse(readFileSync(new URL('../../deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json', import.meta.url), 'utf8'));
const receipt = evm.seal;
const TRUSTED = [receipt.public_key];
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
const BLOCKHASH = b58encode(createHash('sha256').update('blockhash').digest());

function newSolanaKeypair() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const j = privateKey.export({ format: 'jwk' });
  return keypairFromSolanaJson([...Buffer.from(j.d, 'base64url'), ...Buffer.from(j.x, 'base64url')]);
}
const anchorKp = newSolanaKeypair();
const otherKp = newSolanaKeypair();
const MEMO = buildMemo(deriveAnchorIds(sealFromReceipt(receipt)));

function makeTx({ kp = anchorKp, memo = MEMO, programId = MEMO_PROGRAM_ID } = {}) {
  const msg = buildMemoMessage({ payer32: kp.publicKey, recentBlockhash: BLOCKHASH, memo, programId });
  return signTransaction(msg, kp.privateKey);
}

function mockRpc({ wire, err = null, status = 'finalized', missing = false } = {}) {
  return async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    const reply = (result) => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) });
    if (method === 'getTransaction') {
      assert.equal(params[1].commitment, 'finalized');
      return reply(missing ? null : { slot: 4242, blockTime: 1791300000, meta: { err }, transaction: [Buffer.from(wire).toString('base64'), 'base64'] });
    }
    if (method === 'getSignatureStatuses') return reply({ value: [{ slot: 4242, confirmationStatus: status, err }] });
    throw new Error(`unexpected rpc ${method}`);
  };
}
const run = (tx, extra = {}) => verifySolanaAnchor({
  signature: tx.signature, receipt, expectedSigner: anchorKp.pubkey, cluster: 'devnet', rpcUrl: 'http://mock',
  trustedPublicKeysB64: TRUSTED, fetchImpl: mockRpc({ wire: tx.wire, ...extra.rpc }), ...extra.opts,
});

test('memo is the canonical compact form and matches the EVM anchor ids byte for byte', () => {
  const a = evm.seal.anchor;
  assert.equal(MEMO, `${ANCHOR_SCHEME}|rid=${a.receipt_id.slice(2)}|ph=${a.payload_hash.slice(2)}|kid=${a.kid.slice(2, 18)}|obs=${a.observed_at}`);
  assert.ok(Buffer.byteLength(MEMO) < 566);
});

test('base58 + wire format round-trip', () => {
  assert.equal(b58encode(b58decode(MEMO_PROGRAM_ID)), MEMO_PROGRAM_ID);
  assert.equal(b58decode(SYSTEM_PROGRAM).length, 32);
  const tx = makeTx();
  const t = parseTransaction(tx.wire);
  assert.equal(b58encode(t.signatures[0]), tx.signature);
  assert.equal(b58encode(t.accountKeys[1]), MEMO_PROGRAM_ID);
  assert.equal(Buffer.from(t.instructions[0].data).toString(), MEMO);
});

test('genuine anchor → VALID', async () => {
  const r = await run(makeTx());
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.reason, 'ok');
  assert.equal(r.signer, anchorKp.pubkey);
  assert.equal(r.program, MEMO_PROGRAM_ID);
  assert.equal(r.onchain_memo, MEMO);
});

test('altered memo → INVALID', async () => {
  for (const memo of [MEMO.replace('obs=1790473960', 'obs=1790473961'), MEMO + ' ', MEMO.toUpperCase(), MEMO.replace('|rid=b9', '|rid=b8')]) {
    const r = await run(makeTx({ memo }));
    assert.equal(r.valid, false);
    assert.match(r.reason, /not byte-identical/);
  }
});

test('different signer → INVALID', async () => {
  const r = await run(makeTx({ kp: otherKp }));
  assert.equal(r.valid, false);
  assert.match(r.reason, /!= announced/);
});

test('altered receipt → INVALID (canonical, signature, emitted_at)', async () => {
  const tx = makeTx();
  const cases = [
    { ...receipt, canonical: receipt.canonical.replace('risk_tier=critical', 'risk_tier=low') },
    { ...receipt, signature: Buffer.from(Buffer.from(receipt.signature, 'base64').map((b, i) => (i === 100 ? b ^ 1 : b))).toString('base64') },
    { ...receipt, emitted_at: receipt.emitted_at + 1 },
  ];
  for (const bad of cases) {
    const r = await run(tx, { opts: { receipt: bad } });
    assert.equal(r.valid, false, `should reject: ${r.reason}`);
  }
});

test('tx of another program carrying the same bytes → INVALID', async () => {
  const r = await run(makeTx({ programId: SYSTEM_PROGRAM }));
  assert.equal(r.valid, false);
  assert.match(r.reason, /is not SPL Memo/);
});

test('not finalized / failed / missing / forged Ed25519 / untrusted ML-DSA key → INVALID', async () => {
  const tx = makeTx();
  assert.match((await run(tx, { rpc: { missing: true } })).reason, /not found at finalized/);
  assert.match((await run(tx, { rpc: { err: { InstructionError: [0, 'Custom'] } } })).reason, /failed on-chain/);
  assert.match((await run(tx, { rpc: { status: 'confirmed' } })).reason, /not finalized/);
  // RPC serves a tx whose message was altered after signing (memo swapped, signature kept).
  const forged = Buffer.from(tx.wire); forged[forged.length - 1] ^= 1;
  assert.match((await run(tx, { rpc: { wire: forged } })).reason, /Ed25519 signature/);
  // RPC serves a different tx than the one asked for.
  assert.match((await run(tx, { rpc: { wire: makeTx({ memo: MEMO + 'x' }).wire } })).reason, /first signature differs/);
  assert.match((await run(tx, { opts: { trustedPublicKeysB64: ['AAAA'] } })).reason, /not in trusted set/);
  assert.match((await run(tx, { opts: { expectedSigner: undefined } })).reason, /expectedSigner/);
});
