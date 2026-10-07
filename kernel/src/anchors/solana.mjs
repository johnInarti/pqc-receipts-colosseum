/**
 * Solana time proof (SPL Memo v2, scheme fractalai.pqc-receipt-anchor/1) — spec §7.3.
 *   - the RPC must serve the pinned cluster (getGenesisHash), test clusters are marked;
 *   - the tx must be `finalized` (getTransaction at finalized + getSignatureStatuses, same slot), meta.err null;
 *   - blockTime is REQUIRED (no time → no time proof);
 *   - raw bytes are parsed locally: exactly one signature, signer = an ANNOUNCED anchor key for that cluster,
 *     Ed25519 verified locally over the message, no address lookup tables, exactly ONE instruction, to
 *     Memo v2, listing the signer; memo bytes == memo rebuilt from the SIGNED receipt (incl. obs = signed time);
 *   - signed time ≤ blockTime + skew.
 * Run on every configured RPC; facts (slot, blockTime, raw bytes) must agree.
 */
import { C, KernelError, fail } from '../codes.mjs';
import { rpcCall, sameFacts } from '../rpc.mjs';
import { ed25519Verify, sha256hex } from '../crypto.mjs';
import { b64decodeStrict, isPlainObject } from '../hygiene.mjs';
import { b58decode, b58encode, buildMemo, parseTransaction, MEMO_PROGRAM_ID } from './solana-wire.mjs';

function b64any(s) {
  // getTransaction(base64) returns standard padded base64; reuse the strict decoder (no length constraint).
  return b64decodeStrict(s, undefined, 'transaction');
}

async function onOneRpc(url, { cluster, sig, sigBytes, signers, expectedMemo, signedTime, policy, fetchImpl, timeoutMs }) {
  const call = (m, p) => rpcCall(url, m, p, { fetchImpl, timeoutMs });
  const genesis = await call('getGenesisHash', []);
  if (genesis !== cluster.genesis_hash) fail(C.SOL_GENESIS_MISMATCH, `RPC genesis ${String(genesis).slice(0, 44)} is not the pinned ${cluster.name} genesis`);
  const tx = await call('getTransaction', [sig, { encoding: 'base64', commitment: 'finalized', maxSupportedTransactionVersion: 0 }]);
  if (!isPlainObject(tx)) fail(C.ANCHOR_NOT_FOUND, 'transaction not found at finalized commitment');
  if (!isPlainObject(tx.meta) || tx.meta.err !== null) fail(C.ANCHOR_TX_FAILED, 'transaction failed or has no meta');
  if (!Number.isSafeInteger(tx.slot) || tx.slot < 0) fail(C.SOL_TX_MALFORMED, 'slot missing');
  if (!Number.isSafeInteger(tx.blockTime) || tx.blockTime <= 0) fail(C.SOL_NO_BLOCKTIME, 'finalized transaction has no blockTime — no time proof');
  const st = await call('getSignatureStatuses', [[sig], { searchTransactionHistory: true }]);
  const s0 = isPlainObject(st) && Array.isArray(st.value) ? st.value[0] : null;
  if (!isPlainObject(s0) || s0.confirmationStatus !== 'finalized' || s0.err !== null) fail(C.SOL_NOT_FINALIZED, 'signature status is not finalized/ok');
  if (s0.slot !== tx.slot) fail(C.SOL_STATUS_SLOT, `status slot ${s0.slot} != transaction slot ${tx.slot}`);
  const t = Array.isArray(tx.transaction) ? tx.transaction : null;
  if (!t || t.length !== 2 || t[1] !== 'base64' || typeof t[0] !== 'string') fail(C.SOL_TX_MALFORMED, 'transaction not returned as [base64, "base64"]');
  const wire = b64any(t[0]);
  const p = parseTransaction(wire);
  if (p.signatures.length !== 1) fail(C.SOL_SIGNER_COUNT, `anchor tx must have exactly one signer, has ${p.signatures.length}`);
  if (!p.signatures[0].every((b, k) => b === sigBytes[k])) fail(C.SOL_SIGNATURE_MISMATCH, 'RPC returned a transaction whose signature is not the requested one');
  if (p.addressTableLookups) fail(C.SOL_LOOKUP_TABLES, 'address lookup tables are not accepted in an anchor tx');
  const signerBytes = p.accountKeys[0];
  const signer = b58encode(signerBytes);
  if (!ed25519Verify(p.signatures[0], p.message, signerBytes)) fail(C.SOL_ED25519_INVALID, 'Ed25519 signature over the message does not verify');
  if (!signers.includes(signer)) fail(C.SOL_SIGNER_NOT_ANNOUNCED, `signer ${signer} is not an announced anchor key for ${cluster.name}`);
  if (p.instructions.length !== 1) fail(C.SOL_INSTRUCTION_COUNT, `anchor tx must carry exactly 1 instruction, has ${p.instructions.length}`);
  const ix = p.instructions[0];
  if (b58encode(p.accountKeys[ix.programIdIndex]) !== MEMO_PROGRAM_ID) fail(C.SOL_NOT_MEMO, 'the instruction is not SPL Memo v2');
  if (!ix.accounts.includes(0)) fail(C.SOL_MEMO_SIGNER, 'memo instruction does not list the signer');
  const expected = new TextEncoder().encode(expectedMemo);
  if (ix.data.length !== expected.length || !ix.data.every((b, k) => b === expected[k])) fail(C.SOL_MEMO_MISMATCH, 'on-chain memo is not byte-identical to the memo rebuilt from the signed receipt');
  if (signedTime > tx.blockTime + policy.skew) fail(C.ANCHOR_FORWARD_DATED, `signed time ${signedTime} after blockTime ${tx.blockTime}`);
  return { slot: tx.slot, time: tx.blockTime, signer, wire_sha256: sha256hex(wire), finalized: true };
}

/**
 * @param {object} ref  { chain:'solana', cluster, signature, signer? }
 * @param {object} ctx  { roots, ids, signedTime, rpcUrls, policy, fetchImpl, timeoutMs, solanaSigners? }
 */
export async function verifySolanaAnchor(ref, ctx) {
  const clusters = ctx.roots.anchors?.solana?.clusters || {};
  const name = ref.cluster;
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(clusters, name)) fail(C.ANCHOR_CHAIN_NOT_PINNED, `Solana cluster ${JSON.stringify(name)} is not pinned`);
  const cluster = { name, ...clusters[name] };
  const sigBytes = b58decode(ref.signature, 64);
  const signers = ctx.solanaSigners ?? (ctx.roots.anchors.solana.announced_signers?.[name] || []);
  if (ref.signer !== undefined && !signers.includes(ref.signer)) fail(C.SOL_SIGNER_NOT_ANNOUNCED, `reference names signer ${String(ref.signer).slice(0, 44)}, not announced for ${name}`);
  if (ctx.signedTime === null) fail(C.ANCHOR_REQUIRES_SIGNED_TIME, 'this kind signs no time; obs cannot be bound');
  const expectedMemo = buildMemo({ ...ctx.ids, observed_at: ctx.signedTime });
  const urls = ctx.rpcUrls?.length ? ctx.rpcUrls : (cluster.default_rpc ? [cluster.default_rpc] : []);
  if (urls.length === 0) fail(C.ANCHOR_NO_RPC, `no RPC configured for Solana ${name}`);
  if (urls.length < ctx.policy.rpcQuorum) fail(C.RPC_QUORUM, `policy requires ${ctx.policy.rpcQuorum} independent RPCs, ${urls.length} configured`);
  const results = [];
  for (const url of urls) {
    try { results.push(await onOneRpc(url, { cluster, sig: ref.signature, sigBytes, signers, expectedMemo, signedTime: ctx.signedTime, policy: ctx.policy, fetchImpl: ctx.fetchImpl, timeoutMs: ctx.timeoutMs })); }
    catch (e) { if (e instanceof KernelError) { e.detail = `${e.detail} [rpc ${results.length + 1}/${urls.length}]`; throw e; } throw new KernelError(C.RPC_ERROR, String(e?.message ?? e)); }
  }
  for (const r of results.slice(1)) if (!sameFacts(results[0], r, ['slot', 'time', 'signer', 'wire_sha256'])) fail(C.RPC_DISAGREEMENT, 'independent RPCs disagree on the anchor transaction');
  return {
    chain: `solana:${name}`, signature: ref.signature, slot: results[0].slot, time: results[0].time, signer: results[0].signer,
    memo: expectedMemo, finalized: true, rpc_count: results.length, network_class: cluster.network_class,
    anchorer_known: true,
  };
}
