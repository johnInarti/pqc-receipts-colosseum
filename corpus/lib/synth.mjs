/**
 * Deterministic synthetic material for the corpus generator: test ML-DSA-65 keys (fixed seeds,
 * deterministic signing), test key directories and trust roots, MIDAS / seal / served-proof receipts,
 * EVM and Solana JSON-RPC transcripts. TEST KEYS ONLY — never trusted by the baked roots.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  jcs, jcsSigned, sha256hex, kidForKey, b64encode, directoryRoot, KEY_DIR_DOMAIN, SERVED_PREFIX, SEAL_SCHEMA,
  RECEIPT_ANCHORED_TOPIC, b58encode, b58decode, buildMemo, shortvec, MEMO_PROGRAM_ID, BAKED_ROOTS,
} from '../../kernel/src/index.mjs';

const DET = { extraEntropy: false };
const enc = (s) => new TextEncoder().encode(s);
export const seed = (tag) => { const h = sha256hex(`fractalai-corpus-seed/${tag}`); return Uint8Array.from(h.match(/../g).slice(0, 32).map((x) => parseInt(x, 16))); };

export function mlKey(tag) {
  const kp = ml_dsa65.keygen(seed(tag));
  const pk = b64encode(kp.publicKey);
  return { tag, sk: kp.secretKey, pk, kid: kidForKey(pk), sign: (msg) => b64encode(ml_dsa65.sign(enc(msg), kp.secretKey, DET)) };
}
export function edKey(tag) {
  const sk = seed(`ed25519/${tag}`);
  const pub = ed25519.getPublicKey(sk);
  return { tag, sk, pub, b58: b58encode(pub), sign: (m) => ed25519.sign(m, sk) };
}

export function directory(keys, gov, { epoch, prevRoot = '0'.repeat(64), mutateKeys } = {}) {
  const ks = keys.map((k) => ({ kid: k.kid ?? k.key.kid, use: k.use ?? 'x402-receipt', algorithm: 'ML-DSA-65 (FIPS-204)', public_key_b64: k.key.pk, added_at: 0, status: k.status, not_before: k.not_before ?? null, not_after: k.not_after ?? null, ...(k.revoked_at !== undefined ? { revoked_at: k.revoked_at } : {}) }));
  if (mutateKeys) mutateKeys(ks);
  const root = directoryRoot(ks, prevRoot, epoch, gov.pk);
  const signed_message = `${KEY_DIR_DOMAIN}\n${root}`;
  return { spec: KEY_DIR_DOMAIN, issuer: 'corpus-test', epoch, prev_root: prevRoot, root, keys: ks, signed_message, signature: gov.sign(signed_message), directory_public_key: gov.pk };
}

export function testRoots(gov, checkpointDir, { solanaSigners } = {}) {
  const r = JSON.parse(JSON.stringify(BAKED_ROOTS));
  r.issuer = 'corpus TEST roots (never baked)';
  r.governance = { ...r.governance, public_key_b64: gov.pk, kid: gov.kid };
  r.directory_checkpoint = { ...r.directory_checkpoint, epoch: checkpointDir.epoch, root: checkpointDir.root, prev_root: checkpointDir.prev_root, known_previous_roots: {} };
  if (solanaSigners) r.anchors.solana.announced_signers = { ...r.anchors.solana.announced_signers, devnet: solanaSigners };
  return r;
}

export const MIDAS_FIELDS = (o = {}) => ({
  address: '0x00000000000000000000000000000000000000aa', chain_id: '1', health_factor: '1.0123', threshold: '1.99',
  collateral_usd: '1000.5', debt_usd: '900.25', risk_tier: 'critical', observed_at: '1790499990', source: 'corpus-test',
  snapshot_hash: '0'.repeat(64), emitted_at: '1790500000', ...o,
});
export function midasReceipt(key, fields = MIDAS_FIELDS()) {
  const canonical = ['FRACTALAI-midas-alert-v1', ...Object.entries(fields).map(([k, v]) => `${k}=${v}`)].join('\n');
  const id = sha256hex(canonical);
  const served_message = `${SERVED_PREFIX}\nmidas-alert\n${id}`;
  return { receipt_id: id, canonical, domain: 'FRACTALAI-midas-alert-v1', served_domain: `${SERVED_PREFIX}\nmidas-alert`, served_message, signature: key.sign(served_message), public_key: key.pk, algorithm: 'ml-dsa-65', emitted_at: Number(fields.emitted_at) };
}
export function sealReceipt(key, body, domain = `${SERVED_PREFIX}\nx402-witness`) {
  const cid = sha256hex(jcsSigned(body));
  return { algorithm: 'ml-dsa-65', domain, content_id: cid, public_key: key.pk, signature: key.sign(`${domain}\n${cid}`), body };
}
export const sealBody = (o = {}) => ({ schema: SEAL_SCHEMA, resource: '/api/x402/thing', scheme: 'exact', network: 'eip155:8453', asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', payTo: '0xc13789e82661635d9cea38a53a0390cf9939ef4f', amount: '20000', payer: '0x9ddd0b192480d9f0a2eb0147cd56f67c2e249b06', transaction: '0x' + '11'.repeat(32), success: true, response_sha256: null, sealed_at: '2026-10-01T00:00:00.000Z', ...o });
export function servedProof(key, route, digest, domain = SERVED_PREFIX) {
  const signed_message = `${domain}\n${route}\n${digest}`;
  return { profile: 'x402-served', domain, route_id: route, digest, signed_message, signature: key.sign(signed_message), public_key: key.pk };
}

/** Anchor ids exactly as the kernel derives them (receipt_id = sha256(sig bytes), payload = sha256(message)). */
export function idsOf(sigB64, message, pkB64) {
  const sig = Uint8Array.from(Buffer.from(sigB64, 'base64'));
  return { receipt_id: sha256hex(sig), payload_hash: sha256hex(message), kid16: sha256hex(pkB64).slice(0, 16) };
}

const hex = (n) => '0x' + BigInt(n).toString(16);
const pad = (h) => h.replace(/^0x/, '').toLowerCase().padStart(64, '0');
export const RUNTIME = () => null; // set by gen.mjs from a recorded eth_getCode

/** Synthetic EVM node transcript (all calls the kernel may make, keyed by url+method+params). */
export function evmTranscript({ url, chainId, contract, code, ids, observedAt, anchoredBy, blockNumber, blockTime, blockHash = '0x' + sha256hex(`blk/${blockNumber}`), headTime, head = blockNumber + 100, finalized = blockNumber + 50, tx = '0x' + sha256hex(`tx/${ids.receipt_id}`), logIndex = 0, mutateLog, mutateBlock, payloadHash, kid }) {
  const log = {
    address: contract, topics: [RECEIPT_ANCHORED_TOPIC, '0x' + ids.receipt_id, '0x' + (payloadHash ?? ids.payload_hash), '0x' + (kid ?? ids.kid16) + '0'.repeat(48)],
    data: '0x' + pad(hex(observedAt)) + pad(anchoredBy) + pad(hex(blockTime)), blockNumber: hex(blockNumber), blockHash, transactionHash: tx, transactionIndex: '0x0', logIndex: hex(logIndex), removed: false,
  };
  if (mutateLog) mutateLog(log);
  const block = { number: hex(blockNumber), hash: blockHash, timestamp: hex(headTime ?? blockTime) };
  if (mutateBlock) mutateBlock(block);
  return [
    { url, method: 'eth_chainId', params: [], result: hex(chainId) },
    { url, method: 'eth_getCode', params: [contract, 'latest'], result: code },
    { url, method: 'eth_getTransactionReceipt', params: [tx], result: { status: '0x1', transactionHash: tx, blockNumber: hex(blockNumber), blockHash, logs: [log] } },
    { url, method: 'eth_getLogs', params: [{ address: contract, topics: [RECEIPT_ANCHORED_TOPIC, '0x' + ids.receipt_id], fromBlock: hex(blockNumber), toBlock: hex(blockNumber) }], result: [log] },
    { url, method: 'eth_getBlockByNumber', params: [hex(blockNumber), false], result: block },
    { url, method: 'eth_blockNumber', params: [], result: hex(head) },
    { url, method: 'eth_getBlockByNumber', params: ['finalized', false], result: { number: hex(finalized) } },
  ];
}

// ── Solana synthetic transactions ──
const BH = b58encode(Uint8Array.from(sha256hex('corpus-blockhash').match(/../g).map((x) => parseInt(x, 16))));
export const SYSTEM = '11111111111111111111111111111111';
export const MEMO_V1 = 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo';
export function solMessage({ payer, extraKeys = [], ixs, v0 = false, lookups = 0, nsig = 1 }) {
  const keys = [payer, ...extraKeys.map((k) => b58decode(k))];
  const body = [nsig, 0, extraKeys.length, ...shortvec(keys.length), ...keys.flatMap((k) => [...k]), ...b58decode(BH),
    ...shortvec(ixs.length), ...ixs.flatMap((ix) => [ix.prog, ...shortvec(ix.accts.length), ...ix.accts, ...shortvec(ix.data.length), ...ix.data])];
  if (v0) { body.push(...shortvec(lookups)); for (let i = 0; i < lookups; i++) body.push(...b58decode(SYSTEM), ...shortvec(1), 0, ...shortvec(0)); }
  return Uint8Array.from(v0 ? [0x80, ...body] : body);
}
export function solTx(msg, signer) {
  const sig = signer.sign(msg);
  return { signature: b58encode(sig), wire: Uint8Array.from([...shortvec(1), ...sig, ...msg]) };
}
export const memoIx = (prog, memo) => ({ prog, accts: [0], data: [...enc(memo)] });
export function solTranscript({ url, tx, wire = tx.wire, slot = 4242, statusSlot = slot, blockTime = 1791342896, genesis = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG', status = 'finalized', err = null }) {
  return [
    { url, method: 'getGenesisHash', params: [], result: genesis },
    { url, method: 'getTransaction', params: [tx.signature, { encoding: 'base64', commitment: 'finalized', maxSupportedTransactionVersion: 0 }], result: { slot, blockTime, meta: { err }, transaction: [Buffer.from(wire).toString('base64'), 'base64'] } },
    { url, method: 'getSignatureStatuses', params: [[tx.signature], { searchTransactionHistory: true }], result: { context: { slot: slot + 10 }, value: [{ slot: statusSlot, confirmations: null, err, confirmationStatus: status }] } },
  ];
}
export { buildMemo, MEMO_PROGRAM_ID, jcs };
