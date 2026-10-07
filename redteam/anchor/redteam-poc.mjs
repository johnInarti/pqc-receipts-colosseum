#!/usr/bin/env node
// Red-team PoC runner (offline, mocked RPC, real ML-DSA-65 + Ed25519). Runs each attack against the verifier in
// --src (default ./src) and prints ACCEPTED (attack works) / REFUSED. Compare: pre-patch vs patched src.
//   node redteam-poc.mjs --src /path/to/pre-patch/verifier/src
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const i = process.argv.indexOf('--src');
const src = path.resolve(i > 0 ? process.argv[i + 1] : path.join(here, 'src'));
const S = await import(path.join(src, 'solana-anchor.mjs'));
const E = await import(path.join(src, 'verify-anchor.mjs'));
const ARC = JSON.parse(readFileSync(path.join(here, '..', 'deployments', 'anchors', 'PQCReceiptAnchor-5042-fe62b072.json'), 'utf8'));
const R = ARC.seal;
const out = [];
const report = (id, what, r) => out.push(`${r.valid ? 'ACCEPTED' : 'REFUSED '}  ${id.padEnd(6)} ${what}\n          → ${r.reason}`);

// ── Solana ──
const { privateKey } = generateKeyPairSync('ed25519');
const j = privateKey.export({ format: 'jwk' });
const kp = S.keypairFromSolanaJson([...Buffer.from(j.d, 'base64url'), ...Buffer.from(j.x, 'base64url')]);
const BH = S.b58encode(createHash('sha256').update('bh').digest());
const tx = (memo) => S.signTransaction(S.buildMemoMessage({ payer32: kp.publicKey, recentBlockhash: BH, memo }), kp.privateKey);
const node = (wire, { blockTime = 1791342896, genesis = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG' } = {}) => async (_u, init) => {
  const { method } = JSON.parse(init.body);
  const reply = (result) => ({ ok: true, json: async () => ({ result }) });
  if (method === 'getGenesisHash') return reply(genesis);
  if (method === 'getTransaction') return reply({ slot: 1, blockTime, meta: { err: null }, transaction: [Buffer.from(wire).toString('base64'), 'base64'] });
  if (method === 'getSignatureStatuses') return reply({ value: [{ slot: 1, confirmationStatus: 'finalized', err: null }] });
  throw new Error(method);
};
const memo = S.buildMemo(S.deriveAnchorIds(S.sealFromReceipt(R)));
const t0 = tx(memo);
const run = (t, p) => S.verifySolanaAnchor({ signature: t.signature, receipt: R, expectedSigner: kp.pubkey, cluster: 'devnet', rpcUrl: 'http://x', trustedPublicKeysB64: [R.public_key], fetchImpl: node(t.wire), ...p });
report('S0', 'control: genuine devnet memo', await run(t0));
report('RT-S2', 'cluster confusion: devnet tx served by an RPC, verifier told "mainnet-beta"', await run(t0, { cluster: 'mainnet-beta', fetchImpl: node(t0.wire) }));
report('RT-S3', 'finalized tx with blockTime = null (no time at all)', await run(t0, { fetchImpl: node(t0.wire, { blockTime: null }) }));
const fakeObs = memo.replace(/obs=\d+$/, 'obs=1600000000');
const t1 = tx(fakeObs);
report('RT-S5', 'receipt JSON re-dressed with unsigned emitted_at=1600000000 + matching memo', await run(t1, { receipt: { ...R, emitted_at: 1600000000 } }));

// ── EVM ──
const ADDR = '0x1f0d2774943250a7eb179e960203ea86319a8181';
const pad = (h) => h.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const hx = (n) => '0x' + BigInt(n).toString(16);
const RUNTIME = readFileSync(path.join(here, 'test', 'fixtures', 'PQCReceiptAnchor.runtime.hex'), 'utf8').trim();
const ids = { receipt_id: R.anchor.receipt_id, payload_hash: R.anchor.payload_hash, kid: R.anchor.kid };
const evm = ({ observedAt = 1790473960, code = RUNTIME } = {}) => async (_u, init) => {
  const { method, params } = JSON.parse(init.body);
  const reply = (result) => ({ ok: true, json: async () => ({ result }) });
  const log = { address: ADDR, topics: ['0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184', ids.receipt_id, ids.payload_hash, ids.kid], data: '0x' + pad(hx(observedAt)) + pad('0xc13789e82661635d9cea38a53a0390cf9939ef4f') + pad(hx(1791042087)), blockNumber: hx(24072596), blockHash: '0x' + '22'.repeat(32), transactionHash: '0x' + 'ab'.repeat(32), logIndex: '0x5' };
  if (method === 'eth_chainId') return reply('0x13b2');
  if (method === 'eth_getCode') return reply(code);
  if (method === 'eth_getLogs') return reply([log]);
  if (method === 'eth_blockNumber') return reply(hx(24072700));
  if (method === 'eth_getBlockByNumber') return reply(params[0] === 'finalized' ? { number: hx(24072650) } : { number: params[0], hash: '0x' + '22'.repeat(32), timestamp: hx(1791042087) });
  throw new Error(method);
};
const ref = { chain_id: 5042, contract: ADDR };
report('RT-E1', 'the REAL Arc mainnet anchor (MIDAS receipt shape) — should be ACCEPTED', await E.verifyAnchoredSeal({ ...R, anchor: ref }, { trustedPublicKeysB64: [R.public_key], rpcUrl: 'http://x', fetchImpl: evm() }));
report('RT-E5', 'same anchor but on-chain observedAt = 1 (squatter front-ran with correct bytes)', await E.verifyAnchoredSeal({ ...R, anchor: ref }, { trustedPublicKeysB64: [R.public_key], rpcUrl: 'http://x', fetchImpl: evm({ observedAt: 1 }) }));
console.log(`verifier: ${src}\n` + out.join('\n'));
