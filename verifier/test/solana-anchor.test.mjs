/**
 * solana-anchor — the REAL public MIDAS receipt fe62b072… (ML-DSA-65, production key), REAL Ed25519
 * transactions built and signed with the same code that anchors on devnet/mainnet, and a mocked Solana
 * JSON-RPC answering getGenesisHash / getTransaction / getSignatureStatuses the way a devnet node does.
 * Migrated 2026-10-07 to Trust Kernel v2 semantics: the test signer is an explicit announced-signer OVERRIDE
 * (expectedSigner), devnet is marked "test", reasons are kernel codes. Fail-closed everywhere.
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
    const { id, method, params } = JSON.parse(init.body);
    const reply = (result) => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => JSON.stringify({ jsonrpc: '2.0', id, result }) });
    if (method === 'getGenesisHash') return reply('EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG');
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
  assert.match(r.reason, /^ok \(devnet is a TEST cluster/);
  assert.equal(r.network_class, 'test');
  assert.equal(r.signer, anchorKp.pubkey);
  assert.equal(r.program, MEMO_PROGRAM_ID);
  assert.equal(r.expected_memo, MEMO);
  assert.ok(r.verdict.overrides.includes('solanaSigners'), 'the test signer is an explicit override');
});

test('altered memo → INVALID', async () => {
  for (const memo of [MEMO.replace('obs=1790473960', 'obs=1790473961'), MEMO + ' ', MEMO.toUpperCase(), MEMO.replace('|rid=b9', '|rid=b8')]) {
    const r = await run(makeTx({ memo }));
    assert.equal(r.valid, false);
    assert.match(r.reason, /SOL_MEMO_MISMATCH/);
  }
});

test('different signer → INVALID', async () => {
  const r = await run(makeTx({ kp: otherKp }));
  assert.equal(r.valid, false);
  assert.match(r.reason, /SOL_SIGNER_NOT_ANNOUNCED/);
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
  assert.match(r.reason, /SOL_NOT_MEMO/);
});

test('not finalized / failed / missing / forged Ed25519 / untrusted ML-DSA key → INVALID', async () => {
  const tx = makeTx();
  assert.match((await run(tx, { rpc: { missing: true } })).reason, /ANCHOR_NOT_FOUND/);
  assert.match((await run(tx, { rpc: { err: { InstructionError: [0, 'Custom'] } } })).reason, /ANCHOR_TX_FAILED/);
  assert.match((await run(tx, { rpc: { status: 'confirmed' } })).reason, /SOL_NOT_FINALIZED/);
  // RPC serves a tx whose message was altered after signing (memo swapped, signature kept).
  const forged = Buffer.from(tx.wire); forged[forged.length - 1] ^= 1;
  assert.match((await run(tx, { rpc: { wire: forged } })).reason, /SOL_ED25519_INVALID/);
  // RPC serves a different tx than the one asked for.
  assert.match((await run(tx, { rpc: { wire: makeTx({ memo: MEMO + 'x' }).wire } })).reason, /SOL_SIGNATURE_MISMATCH/);
  assert.match((await run(tx, { opts: { trustedPublicKeysB64: ['AAAA'] } })).reason, /KEY_NOT_IN_PINNED_SET/);
  assert.match((await run(tx, { opts: { expectedSigner: undefined } })).reason, /SOL_SIGNER_NOT_ANNOUNCED/);
});
