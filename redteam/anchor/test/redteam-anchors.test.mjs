/**
 * RED-TEAM regression suite for the EVM (PQCReceiptAnchor) and Solana (SPL Memo) anchor verifiers.
 * Every test is an attack that the pre-patch verifier either accepted or could not evaluate; ids RT-Ex / RT-Sx match
 * the red-team report. Real ML-DSA-65 (the public production receipt fe62b072… + fresh keys), real Ed25519,
 * mocked JSON-RPC only. No network.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { generateKeypair } from '../src/self-attest.mjs';
import { signSeal, NOTARY_DOMAIN } from '../src/witness-core.mjs';
import {
  verifyAnchoredSeal, deriveAnchorIds as evmIds, trustedKeysFromDirectory, RECEIPT_ANCHORED_TOPIC,
  PQC_ANCHOR_RUNTIME_CODEHASH, KNOWN_DEPLOYMENTS,
} from '../src/verify-anchor.mjs';
import {
  verifySolanaAnchor, buildMemo, deriveAnchorIds as solIds, sealFromReceipt, buildMemoMessage, signTransaction,
  parseTransaction, b58encode, b58decode, keypairFromSolanaJson, MEMO_PROGRAM_ID, GENESIS_HASH, keyTrustedAt,
} from '../src/solana-anchor.mjs';

const RUNTIME = readFileSync(new URL('./fixtures/PQCReceiptAnchor.runtime.hex', import.meta.url), 'utf8').trim();
const ARC = JSON.parse(readFileSync(new URL('../../deployments/anchors/PQCReceiptAnchor-5042-fe62b072.json', import.meta.url), 'utf8'));
const MIDAS = ARC.seal; // real production receipt + real Arc anchor reference
const MIDAS_PK = MIDAS.public_key;
const hexN = (n) => '0x' + BigInt(n).toString(16);
const pad = (h) => h.replace(/^0x/, '').toLowerCase().padStart(64, '0');

// ───────────────────────────── EVM mock node ─────────────────────────────
function evmNode({ chainId, contract, code = RUNTIME, logs, blocks, head, finalized, txs = {} }) {
  const calls = [];
  const fetchImpl = async (_u, init) => {
    const { method, params } = JSON.parse(init.body);
    calls.push(method);
    const reply = (result) => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) });
    switch (method) {
      case 'eth_chainId': return reply(hexN(chainId));
      case 'eth_getCode': return reply(params[0].toLowerCase() === contract.toLowerCase() ? code : '0x');
      case 'eth_blockNumber': return reply(hexN(head));
      case 'eth_getBlockByNumber': {
        if (params[0] === 'finalized') return reply(finalized == null ? null : { number: hexN(finalized) });
        const b = blocks[parseInt(params[0], 16)];
        return reply(b ? { number: params[0], hash: b.hash, timestamp: hexN(b.timestamp) } : null);
      }
      case 'eth_getLogs': {
        const f = params[0];
        return reply(logs.filter((l) => l.address.toLowerCase() === f.address && l.topics[1] === f.topics[1]
          && (f.fromBlock === undefined || parseInt(l.blockNumber, 16) >= parseInt(f.fromBlock, 16))
          && (f.toBlock === 'latest' || parseInt(l.blockNumber, 16) <= parseInt(f.toBlock, 16))));
      }
      case 'eth_getTransactionReceipt': return reply(txs[params[0]] ?? null);
      default: throw new Error(`unexpected rpc ${method}`);
    }
  };
  return { fetchImpl, calls };
}
const evLog = ({ contract, ids, payloadHash, kid, observedAt, anchoredBy, anchoredAt, block, blockHash, tx = '0x' + 'ab'.repeat(32), logIndex = 0 }) => ({
  address: contract, topics: [RECEIPT_ANCHORED_TOPIC, ids.receipt_id, payloadHash ?? ids.payload_hash, kid ?? ids.kid],
  data: '0x' + pad(hexN(observedAt)) + pad(anchoredBy) + pad(hexN(anchoredAt)),
  blockNumber: hexN(block), blockHash, transactionHash: tx, logIndex: hexN(logIndex),
});

// The real Arc anchor, reproduced from what the public Arc RPC returned on 2026-10-06.
const ARC_ADDR = KNOWN_DEPLOYMENTS[5042].address;
const ARC_BLOCK = 24072596, ARC_TS = 1791042087, ARC_HASH = '0x22a3a3aa48f72963ac48e46ab07ce6ef920b76bb11d93cb92c6333ea10dc4b2b';
const TREASURY = '0xc13789e82661635d9cea38a53a0390cf9939ef4f';
const MIDAS_IDS = evmIds(sealFromReceipt(MIDAS));
const arcNode = (over = {}) => evmNode({
  chainId: 5042, contract: ARC_ADDR, head: ARC_BLOCK + 100, finalized: ARC_BLOCK + 50,
  blocks: { [ARC_BLOCK]: { hash: ARC_HASH, timestamp: ARC_TS } },
  logs: [evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, observedAt: 1790473960, anchoredBy: TREASURY, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: ARC_HASH, logIndex: 5 })],
  ...over,
});
const arcRef = { scheme: 'fractalai.pqc-receipt-anchor/1', chain_id: 5042, contract: ARC_ADDR, block_number: ARC_BLOCK };

test('RT-E1: the REAL mainnet anchor (MIDAS receipt shape, Arc) verifies — the pre-patch verifier said "seal: missing body"', async () => {
  const r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: arcNode().fetchImpl, rpcUrl: 'http://arc' });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.mode, 'midas-alert');
  assert.equal(r.anchored_at, ARC_TS);
  assert.equal(r.observed_at, 1790473960);
  assert.equal(r.contract_known, true);
  assert.equal(r.finalized, true);
});

test('RT-E2: look-alike contract emitting the same topic with a BACKDATED anchoredAt is refused (code hash)', async () => {
  const FAKE = '0x' + 'fa'.repeat(20);
  const node = evmNode({
    chainId: 5042, contract: FAKE, code: '0x6080604052', head: ARC_BLOCK + 10, finalized: ARC_BLOCK,
    blocks: { [ARC_BLOCK]: { hash: ARC_HASH, timestamp: ARC_TS } },
    logs: [evLog({ contract: FAKE, ids: MIDAS_IDS, observedAt: 1700000000, anchoredBy: TREASURY, anchoredAt: 1700000000, block: ARC_BLOCK, blockHash: ARC_HASH })],
  });
  const r = await verifyAnchoredSeal({ ...MIDAS, emitted_at: undefined, anchor: { ...arcRef, contract: FAKE } }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc', observedAtToleranceSec: 1e9 });
  assert.equal(r.valid, false);
  assert.match(r.reason, /is not PQCReceiptAnchor \(runtime code hash/);
  assert.equal(PQC_ANCHOR_RUNTIME_CODEHASH, '0xe4733ce5c69278cb8072bebfd2500679236551039f896850929d0ceb443f2595');
});

test('RT-E4: anchoredAt is taken from the block header — event/header mismatch, reorged blockHash, removed log → refused', async () => {
  // genuine bytecode can never do this, but a lying RPC can: event says 2023, header says 2026
  let node = arcNode({ logs: [evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, observedAt: 1790473960, anchoredBy: TREASURY, anchoredAt: ARC_TS - 86400 * 400, block: ARC_BLOCK, blockHash: ARC_HASH })] });
  let r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc', observedAtToleranceSec: 1e9 });
  assert.match(r.reason, /event anchoredAt .* != block.timestamp/);
  node = arcNode({ logs: [evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, observedAt: 1790473960, anchoredBy: TREASURY, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: '0x' + '01'.repeat(32) })] });
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc' });
  assert.match(r.reason, /not the canonical block/);
  node = arcNode({ logs: [{ ...evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, observedAt: 1790473960, anchoredBy: TREASURY, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: ARC_HASH }), removed: true }] });
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc' });
  assert.match(r.reason, /removed by a reorg/);
});

test('RT-E3: squatted receiptId (garbage payloadHash by a stranger) → named in the reason; a 2nd anchor in seal.anchors[] rescues it', async () => {
  const SQUATTER = '0x' + '5a'.repeat(20);
  const squat = arcNode({ logs: [evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, payloadHash: '0x' + 'ee'.repeat(32), observedAt: 1, anchoredBy: SQUATTER, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: ARC_HASH })] });
  let r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: squat.fetchImpl, rpcUrl: 'http://arc' });
  assert.equal(r.valid, false);
  assert.match(r.reason, new RegExp(`SQUATTED by ${SQUATTER}`));
  // Fallback: the same receipt also anchored on Arbitrum One; RPC routing by URL.
  const ARB = KNOWN_DEPLOYMENTS[42161].address, ARB_BLOCK = 511335916, ARB_TS = 1791040127, ARB_HASH = '0x' + 'a1'.repeat(32);
  const arb = evmNode({ chainId: 42161, contract: ARB, head: ARB_BLOCK + 5, finalized: ARB_BLOCK, blocks: { [ARB_BLOCK]: { hash: ARB_HASH, timestamp: ARB_TS } },
    logs: [evLog({ contract: ARB, ids: MIDAS_IDS, observedAt: 1790473960, anchoredBy: TREASURY, anchoredAt: ARB_TS, block: ARB_BLOCK, blockHash: ARB_HASH })] });
  const route = async (u, init) => (u === 'http://arb' ? arb.fetchImpl(u, init) : squat.fetchImpl(u, init));
  // rpcUrl is per chain: use the defaults map by passing no rpcUrl and a router keyed on the default URLs.
  const byDefault = async (u, init) => route(u.includes('arbitrum') ? 'http://arb' : 'http://arc', init);
  r = await verifyAnchoredSeal({ ...MIDAS, anchors: [arcRef, { chain_id: 42161, contract: ARB, block_number: ARB_BLOCK }] }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: byDefault });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.chain_id, 42161);
  assert.equal(r.anchors_tried, 2);
});

test('RT-E3b: legit values anchored first by a stranger (front-run copy) → valid unless the anchorer is pinned', async () => {
  const STRANGER = '0x' + '77'.repeat(20);
  const node = arcNode({ logs: [evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, observedAt: 1790473960, anchoredBy: STRANGER, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: ARC_HASH })] });
  let r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc' });
  assert.equal(r.valid, true, 'existence-by-time is still proven: the bytes and the block time are genuine');
  assert.equal(r.anchored_by, STRANGER);
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc', expectedAnchoredBy: TREASURY });
  assert.match(r.reason, /anchoredBy .* != expected/);
});

test('RT-E5: on-chain observedAt must equal the SIGNED time; a forward-dated receipt (signed after its anchor) is refused', async () => {
  const node = arcNode({ logs: [evLog({ contract: ARC_ADDR, ids: MIDAS_IDS, observedAt: 1600000000, anchoredBy: TREASURY, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: ARC_HASH })] });
  let r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: node.fetchImpl, rpcUrl: 'http://arc' });
  assert.match(r.reason, /observedAt 1600000000 != signed time 1790473960/);
  // x402 seal signed "in the future" relative to the block that anchors it
  const kp = generateKeypair(); const pk = Buffer.from(kp.publicKey).toString('base64');
  const body = { schema: 'fractalai.x402-settlement-seal/0.1', sealed_at: new Date((ARC_TS + 7200) * 1000).toISOString() };
  const seal = signSeal(body, { domain: NOTARY_DOMAIN, secretKey: kp.secretKey, publicKey: kp.publicKey });
  const ids = evmIds(seal);
  const n2 = arcNode({ logs: [evLog({ contract: ARC_ADDR, ids, observedAt: ARC_TS + 7200, anchoredBy: TREASURY, anchoredAt: ARC_TS, block: ARC_BLOCK, blockHash: ARC_HASH })] });
  r = await verifyAnchoredSeal({ ...seal, anchor: arcRef }, { trustedPublicKeysB64: [pk], fetchImpl: n2.fetchImpl, rpcUrl: 'http://arc' });
  assert.match(r.reason, /observedAt after anchoredAt|forward-dated/);
});

test('RT-E6/E7: cross-check RPC that disagrees → refused; requireFinalized on a non-finalized block → refused', async () => {
  const good = arcNode();
  const liar = arcNode({ blocks: { [ARC_BLOCK]: { hash: '0x' + '0f'.repeat(32), timestamp: ARC_TS } } });
  const route = async (u, init) => (u === 'http://liar' ? liar.fetchImpl(u, init) : good.fetchImpl(u, init));
  let r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: route, rpcUrl: 'http://arc', crossCheckRpcUrls: ['http://liar'] });
  assert.match(r.reason, /cross-check rpc http:\/\/liar disagrees/);
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: route, rpcUrl: 'http://arc', crossCheckRpcUrls: ['http://arc2'] });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.rpc_cross_checked, 1);
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { trustedPublicKeysB64: [MIDAS_PK], fetchImpl: arcNode({ finalized: ARC_BLOCK - 1 }).fetchImpl, rpcUrl: 'http://arc', requireFinalized: true });
  assert.match(r.reason, /not finalized/);
});

test('RT-E8: key lifecycle judged AT the anchor time — anchored receipts survive key retirement; not_before / revoked enforced', async () => {
  const now = ARC_TS + 400 * 86400;
  const dir = (k) => ({ keys: [{ public_key_b64: MIDAS_PK, ...k }] });
  // retired key (not_after passed NOW) — current-time pin rejects it, anchor-time evaluation accepts it
  const retired = dir({ status: 'retiring', not_before: 0, not_after: ARC_TS + 86400 });
  assert.deepEqual(trustedKeysFromDirectory(retired, now), []);
  let r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { keyDirectory: retired, fetchImpl: arcNode().fetchImpl, rpcUrl: 'http://arc' });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.key_trusted, true);
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { keyDirectory: dir({ status: 'active', not_before: ARC_TS + 1 }), fetchImpl: arcNode().fetchImpl, rpcUrl: 'http://arc' });
  assert.match(r.reason, /not_before/);
  r = await verifyAnchoredSeal({ ...MIDAS, anchor: arcRef }, { keyDirectory: dir({ status: 'revoked' }), fetchImpl: arcNode().fetchImpl, rpcUrl: 'http://arc' });
  assert.match(r.reason, /revoked/);
  assert.equal(keyTrustedAt(dir({ status: 'revoked', revoked_at: ARC_TS + 10 }), MIDAS_PK, ARC_TS).trusted, true);
});

test('RT-E9: trustedKeysFromDirectory honours not_before (a reserved-then-activated key cannot vouch for earlier receipts)', () => {
  assert.deepEqual(trustedKeysFromDirectory({ keys: [{ public_key_b64: 'K', status: 'active', not_before: 2000 }] }, 1000), []);
  assert.deepEqual(trustedKeysFromDirectory({ keys: [{ public_key_b64: 'K', status: 'active', not_before: 2000 }] }, 3000), ['K']);
});

test('RT-E10/S6: non-canonical base64 of the public key (same bytes, different kid string) is refused', async () => {
  const variants = [MIDAS_PK.replace(/=*$/, '') /* unpadded if padded */, MIDAS_PK.slice(0, 40) + '\n' + MIDAS_PK.slice(40), ' ' + MIDAS_PK];
  for (const pk of variants) {
    if (pk === MIDAS_PK) continue;
    assert.deepEqual(Buffer.from(pk, 'base64'), Buffer.from(MIDAS_PK, 'base64'), 'Node decodes it to the same key');
    assert.throws(() => sealFromReceipt({ ...MIDAS, public_key: pk }), /canonical base64/);
    const r = await verifyAnchoredSeal({ ...MIDAS, public_key: pk, anchor: arcRef }, { fetchImpl: arcNode().fetchImpl, rpcUrl: 'http://arc' });
    assert.equal(r.valid, false);
  }
});

// ───────────────────────────── Solana ─────────────────────────────
function newKp() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const j = privateKey.export({ format: 'jwk' });
  return keypairFromSolanaJson([...Buffer.from(j.d, 'base64url'), ...Buffer.from(j.x, 'base64url')]);
}
const SIGNER = newKp(), OTHER = newKp();
const BH = b58encode(createHash('sha256').update('bh').digest());
const SEAL = sealFromReceipt(MIDAS);
const MEMO = buildMemo(solIds(SEAL));
const MEMO_V1 = 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo';
const SYSTEM = '11111111111111111111111111111111';
const sv = (n) => { const o = []; for (;;) { const b = n & 0x7f; n >>= 7; if (!n) { o.push(b); return o; } o.push(b | 0x80); } };

/** Generic message builder: keys[0] = payer (signer, writable); ixs = [{ prog: keyIndex, accts: [...], data: Buffer }]. */
function rawMessage({ payer, extraKeys = [], ixs, v0 = false, lookups = 0, readonlyUnsigned }) {
  const keys = [payer, ...extraKeys.map((k) => b58decode(k))];
  const body = [
    1, 0, readonlyUnsigned ?? extraKeys.length,
    ...sv(keys.length), ...keys.flatMap((k) => [...k]), ...b58decode(BH),
    ...sv(ixs.length), ...ixs.flatMap((ix) => [ix.prog, ...sv(ix.accts.length), ...ix.accts, ...sv(ix.data.length), ...ix.data]),
  ];
  if (v0) { body.push(...sv(lookups)); for (let i = 0; i < lookups; i++) body.push(...b58decode(SYSTEM), ...sv(1), 0, ...sv(0)); }
  return Buffer.from(v0 ? [0x80, ...body] : body);
}
const signed = (msg, kp = SIGNER) => signTransaction(msg, kp.privateKey);
const memoIx = (prog = 1, memo = MEMO) => ({ prog, accts: [0], data: Buffer.from(memo, 'utf8') });

function solNode({ wire, slot = 4242, statusSlot = slot, blockTime = 1791342896, genesis = GENESIS_HASH.devnet, status = 'finalized' }) {
  return async (_u, init) => {
    const { method } = JSON.parse(init.body);
    const reply = (result) => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) });
    if (method === 'getGenesisHash') return reply(genesis);
    if (method === 'getTransaction') return reply({ slot, blockTime, meta: { err: null }, transaction: [Buffer.from(wire).toString('base64'), 'base64'] });
    if (method === 'getSignatureStatuses') return reply({ value: [{ slot: statusSlot, confirmationStatus: status, err: null }] });
    throw new Error(`unexpected ${method}`);
  };
}
const solRun = (tx, { node = {}, ...p } = {}) => verifySolanaAnchor({
  signature: tx.signature, receipt: MIDAS, expectedSigner: SIGNER.pubkey, cluster: 'devnet', rpcUrl: 'http://sol',
  trustedPublicKeysB64: [MIDAS_PK], fetchImpl: solNode({ wire: tx.wire, ...node }), ...p,
});

test('RT-S0 (control): canonical one-memo legacy tx by the announced signer → valid, flagged as TEST cluster', async () => {
  const r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] })));
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.network_class, 'test');
});

test('RT-S1: same memo text signed by someone else / two memos / Memo v1 / memo hidden behind another program (CPI) → refused', async () => {
  let r = await solRun(signed(rawMessage({ payer: OTHER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] }), OTHER));
  assert.match(r.reason, /!= announced/);
  r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx(), memoIx(1, MEMO.replace('obs=', 'obs=9'))] })));
  assert.match(r.reason, /exactly 1 instruction/);
  r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_V1], ixs: [memoIx()] })));
  assert.match(r.reason, /is not SPL Memo/);
  // a program that CPIs into Memo: the memo only exists in inner instructions; top level is the other program
  r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [SYSTEM, MEMO_PROGRAM_ID], ixs: [{ prog: 1, accts: [0, 2], data: Buffer.from(MEMO) }] })));
  assert.match(r.reason, /is not SPL Memo/);
  // durable-nonce shape: AdvanceNonceAccount + memo = 2 instructions
  r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [SYSTEM, MEMO_PROGRAM_ID], ixs: [{ prog: 1, accts: [0], data: Buffer.from([4, 0, 0, 0]) }, memoIx(2)] })));
  assert.match(r.reason, /exactly 1 instruction/);
});

test('RT-S1b: v0 transaction — accepted without lookups, refused with an address lookup table', async () => {
  let r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()], v0: true })));
  assert.equal(r.valid, true, r.reason);
  r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()], v0: true, lookups: 1 })));
  assert.match(r.reason, /lookup tables not accepted/);
});

test('RT-S1c: memo encoding tricks (uppercase rid, NBSP, fullwidth "|", trailing NUL, 0x-prefixed rid) → refused byte-for-byte', async () => {
  const ridHex = solIds(SEAL).receipt_id;
  for (const m of [MEMO.replace(ridHex, ridHex.toUpperCase()), MEMO.replace('|ph=', ' |ph='), MEMO.replace('|kid=', '｜kid='), MEMO + '\u0000', MEMO.replace('rid=', 'rid=0x')]) {
    const r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx(1, m)] })));
    assert.match(r.reason, /not byte-identical/);
  }
});

test('RT-S2: RPC of another cluster (devnet RPC asked as mainnet-beta, or a private validator) → refused by genesis hash', async () => {
  const tx = signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] }));
  let r = await solRun(tx, { cluster: 'mainnet-beta' });
  assert.match(r.reason, /is not mainnet-beta/);
  r = await solRun(tx, { node: { genesis: b58encode(createHash('sha256').update('my-validator').digest()) } });
  assert.match(r.reason, /is not devnet/);
});

test('RT-S3: blockTime null → no time proof → refused', async () => {
  const r = await solRun(signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] })), { node: { blockTime: null } });
  assert.match(r.reason, /no blockTime/);
});

test('RT-S4: RPC inconsistencies — status slot != tx slot, cross-check RPC with another blockTime → refused', async () => {
  const tx = signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] }));
  let r = await solRun(tx, { node: { statusSlot: 4243 } });
  assert.match(r.reason, /status slot/);
  const good = solNode({ wire: tx.wire }), liar = solNode({ wire: tx.wire, blockTime: 1600000000 });
  r = await solRun(tx, { fetchImpl: async (u, i) => (u === 'http://liar' ? liar(u, i) : good(u, i)), crossCheckRpcUrls: ['http://liar'] });
  assert.match(r.reason, /cross-check rpc http:\/\/liar disagrees/);
  r = await solRun(tx, { fetchImpl: async (u, i) => good(u, i), crossCheckRpcUrls: ['http://sol2'] });
  assert.equal(r.valid, true, r.reason);
  assert.equal(r.rpc_cross_checked, 1);
});

test('RT-S5: re-dressed receipt JSON (unsigned emitted_at) + memo with that obs by the announced signer → refused', async () => {
  const fake = 1700000000;
  const forgedMemo = MEMO.replace(/obs=\d+$/, `obs=${fake}`);
  const tx = signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx(1, forgedMemo)] }));
  const r = await solRun(tx, { receipt: { ...MIDAS, emitted_at: fake } });
  assert.equal(r.valid, false);
  assert.match(r.reason, /emitted_at 1700000000 != signed canonical emitted_at 1790473960/);
});

test('RT-S7: truncated / out-of-range wire bytes throw instead of parsing as zeros', () => {
  const tx = signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] }));
  assert.throws(() => parseTransaction(tx.wire.subarray(0, tx.wire.length - 10)), /truncated/);
  const bad = signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [{ prog: 9, accts: [0], data: Buffer.from('x') }] }));
  assert.throws(() => parseTransaction(bad.wire), /outside the static keys/);
  assert.throws(() => parseTransaction(Buffer.concat([tx.wire, Buffer.from([0])])), /trailing/);
});

test('RT-S8: key lifecycle at block_time (Solana)', async () => {
  const tx = signed(rawMessage({ payer: SIGNER.publicKey, extraKeys: [MEMO_PROGRAM_ID], ixs: [memoIx()] }));
  let r = await solRun(tx, { trustedPublicKeysB64: undefined, keyDirectory: { keys: [{ public_key_b64: MIDAS_PK, status: 'retiring', not_before: 0, not_after: 1791342896 + 1 }] } });
  assert.equal(r.valid, true, r.reason);
  r = await solRun(tx, { trustedPublicKeysB64: undefined, keyDirectory: { keys: [{ public_key_b64: MIDAS_PK, status: 'retiring', not_before: 0, not_after: 1791342896 - 1 }] } });
  assert.match(r.reason, /not_after/);
});
