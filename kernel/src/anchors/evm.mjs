/**
 * EVM time proof (PQCReceiptAnchor, scheme fractalai.pqc-receipt-anchor/1) — spec §7.2.
 * Everything that decides comes from the chain and the pinned roots; the anchor reference is a HINT
 * (where to look), never a source of truth:
 *   - contract = roots.anchors.evm[chainId].contract (a reference naming another address is refused);
 *   - keccak256(eth_getCode(contract)) == pinned runtime code hash (a look-alike emitter is refused);
 *   - exactly one ReceiptAnchored(receiptId) log, not removed, 4 topics, 96-byte data;
 *   - payloadHash/kid equal to the values recomputed from the signed bytes (else: SQUATTED, named);
 *   - block header by number: hash == log.blockHash, time := header.timestamp, event anchoredAt == time;
 *   - observedAt == signed time (seconds) and signed time ≤ time + skew;
 *   - confirmations ≥ policy; finalized := RPC `finalized` block ≥ log block.
 * Run independently on every configured RPC; all must succeed and agree.
 */
import { C, KernelError, fail } from '../codes.mjs';
import { rpcCall, sameFacts } from '../rpc.mjs';
import { keccak256hex } from '../crypto.mjs';
import { hexToBytes, isHex0x, qty, toQty, isPlainObject } from '../hygiene.mjs';

export const RECEIPT_ANCHORED_TOPIC = '0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184';
const lc = (s) => String(s).toLowerCase();

async function onOneRpc(url, { chainId, dep, ids, signedTime, ref, policy, fetchImpl, timeoutMs }) {
  const call = (m, p) => rpcCall(url, m, p, { fetchImpl, timeoutMs });
  const live = qty(await call('eth_chainId', []), 'eth_chainId');
  if (live !== chainId) fail(C.ANCHOR_WRONG_CHAIN, `RPC serves chain ${live}, not ${chainId}`);
  const code = await call('eth_getCode', [dep.contract, 'latest']);
  if (typeof code !== 'string' || !/^0x[0-9a-fA-F]+$/.test(code) || code.length <= 2) fail(C.ANCHOR_CODEHASH_MISMATCH, `no contract code at ${dep.contract}`);
  const codehash = keccak256hex(hexToBytes(code));
  if (codehash !== dep.runtime_codehash) fail(C.ANCHOR_CODEHASH_MISMATCH, `runtime code hash ${codehash} != pinned ${dep.runtime_codehash}`);

  const rid = '0x' + ids.receipt_id;
  const match = (l) => isPlainObject(l) && lc(l.address) === dep.contract && Array.isArray(l.topics) && lc(l.topics[0]) === RECEIPT_ANCHORED_TOPIC && lc(l.topics[1]) === rid;
  let log;
  if (ref.tx_hash !== undefined) {
    if (!isHex0x(ref.tx_hash, 64)) fail(C.ANCHOR_REF_MALFORMED, 'tx_hash is not 0x + 64 hex');
    const rc = await call('eth_getTransactionReceipt', [ref.tx_hash]);
    if (!isPlainObject(rc)) fail(C.ANCHOR_NOT_FOUND, 'transaction receipt not found');
    if (rc.status !== '0x1') fail(C.ANCHOR_TX_FAILED, 'anchor transaction did not succeed');
    const cands = (Array.isArray(rc.logs) ? rc.logs : []).filter(match);
    const pick = ref.log_index !== undefined ? cands.filter((l) => qty(l.logIndex, 'logIndex') === ref.log_index) : cands;
    if (pick.length === 0) fail(C.ANCHOR_NOT_FOUND, 'no ReceiptAnchored(receiptId) log from the pinned contract in that transaction');
    if (pick.length > 1) fail(C.ANCHOR_AMBIGUOUS, 'more than one matching log');
    log = pick[0];
    if (lc(log.transactionHash ?? ref.tx_hash) !== lc(ref.tx_hash)) fail(C.ANCHOR_LOG_MALFORMED, 'log transactionHash differs from the requested one');
  } else {
    const from = ref.block_number !== undefined ? ref.block_number : dep.from_block;
    const to = ref.block_number !== undefined ? toQty(ref.block_number) : 'latest';
    const logs = await call('eth_getLogs', [{ address: dep.contract, topics: [RECEIPT_ANCHORED_TOPIC, rid], fromBlock: toQty(from), toBlock: to }]);
    if (!Array.isArray(logs)) fail(C.RPC_ERROR, 'eth_getLogs did not return an array');
    const cands = logs.filter(match);
    if (cands.length === 0) fail(C.ANCHOR_NOT_FOUND, 'no ReceiptAnchored(receiptId) event on the pinned contract');
    if (cands.length > 1) fail(C.ANCHOR_AMBIGUOUS, 'several ReceiptAnchored events for one receiptId (write-once invariant broken)');
    log = cands[0];
  }
  if (log.removed === true) fail(C.ANCHOR_LOG_REMOVED, 'log was removed by a reorg');
  if (log.topics.length !== 4 || typeof log.data !== 'string' || !/^0x[0-9a-fA-F]{192}$/.test(log.data)) fail(C.ANCHOR_LOG_MALFORMED, 'event does not have 4 topics and 96 bytes of data');
  if (!isHex0x(log.blockHash, 64)) fail(C.ANCHOR_LOG_MALFORMED, 'log has no blockHash');
  const blockNumber = qty(log.blockNumber, 'log.blockNumber');
  if (ref.block_number !== undefined && ref.block_number !== blockNumber) fail(C.ANCHOR_BLOCK_MISMATCH, `reference says block ${ref.block_number}, log is in ${blockNumber}`);
  const d = log.data.slice(2);
  const observedAt = Number.parseInt(d.slice(0, 64), 16);
  if (!/^0{24}/.test(d.slice(64, 128)) || !/^0{48}/.test(d.slice(0, 64)) || !/^0{48}/.test(d.slice(128))) fail(C.ANCHOR_LOG_MALFORMED, 'event data has non-canonical padding');
  const anchoredBy = '0x' + d.slice(64 + 24, 128).toLowerCase();
  const eventAnchoredAt = Number.parseInt(d.slice(128, 192), 16);
  if (lc(log.topics[2]) !== '0x' + ids.payload_hash) fail(C.ANCHOR_SQUATTED, `receiptId occupied by ${anchoredBy} with a different payloadHash (write-once slot squatted; anchor elsewhere)`);
  if (lc(log.topics[3]) !== '0x' + ids.kid16 + '0'.repeat(48)) fail(C.ANCHOR_KID_MISMATCH, `receiptId anchored by ${anchoredBy} under another key id`);

  const blk = await call('eth_getBlockByNumber', [toQty(blockNumber), false]);
  if (!isPlainObject(blk)) fail(C.ANCHOR_BLOCK_MISMATCH, `block ${blockNumber} not found`);
  if (lc(blk.hash) !== lc(log.blockHash)) fail(C.ANCHOR_BLOCK_MISMATCH, `log blockHash is not the canonical hash of block ${blockNumber} (reorg or lying RPC)`);
  if (qty(blk.number, 'block.number') !== blockNumber) fail(C.ANCHOR_BLOCK_MISMATCH, 'header number mismatch');
  const time = qty(blk.timestamp, 'block.timestamp');
  if (eventAnchoredAt !== time) fail(C.ANCHOR_TIME_MISMATCH, `event anchoredAt ${eventAnchoredAt} != header timestamp ${time}`);
  if (observedAt !== signedTime) fail(C.ANCHOR_OBSERVED_AT_MISMATCH, `on-chain observedAt ${observedAt} != signed time ${signedTime}`);
  if (signedTime > time + policy.skew) fail(C.ANCHOR_FORWARD_DATED, `signed time ${signedTime} is after the anchor block time ${time}`);

  const head = qty(await call('eth_blockNumber', []), 'eth_blockNumber');
  const confirmations = head - blockNumber + 1;
  if (confirmations < policy.minConfirmations) fail(C.ANCHOR_CONFIRMATIONS, `${confirmations} confirmations < ${policy.minConfirmations}`);
  let finalized = false;
  try {
    const f = await call('eth_getBlockByNumber', ['finalized', false]);
    finalized = isPlainObject(f) && qty(f.number, 'finalized.number') >= blockNumber;
  } catch { finalized = false; }
  return {
    chain: `eip155:${chainId}`, contract: dep.contract, tx_hash: lc(log.transactionHash ?? ref.tx_hash ?? ''), log_index: qty(log.logIndex, 'logIndex'),
    block_number: blockNumber, block_hash: lc(log.blockHash), time, observed_at: observedAt, anchored_by: anchoredBy, finalized,
  };
}

/**
 * @param {object} ref       anchor reference (hint)
 * @param {object} ctx       { roots, ids, signedTime, rpcUrls: string[], policy, fetchImpl, timeoutMs, overrideContracts }
 */
export async function verifyEvmAnchor(ref, ctx) {
  const chainId = ref.chain_id;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) fail(C.ANCHOR_REF_MALFORMED, 'chain_id is not a positive integer');
  const dep = ctx.roots.anchors?.evm?.[String(chainId)];
  if (!dep) fail(C.ANCHOR_CHAIN_NOT_PINNED, `no pinned PQCReceiptAnchor deployment for chain ${chainId}`);
  if (ref.contract !== undefined && lc(ref.contract) !== dep.contract) fail(C.ANCHOR_CONTRACT_NOT_PINNED, `reference names contract ${lc(ref.contract)}, pinned is ${dep.contract}`);
  for (const f of ['block_number', 'log_index']) if (ref[f] !== undefined && !(Number.isSafeInteger(ref[f]) && ref[f] >= 0)) fail(C.ANCHOR_REF_MALFORMED, `${f} must be a non-negative integer`);
  if (ctx.signedTime === null) fail(C.ANCHOR_REQUIRES_SIGNED_TIME, 'this kind signs no time; observedAt cannot be bound');
  const urls = ctx.rpcUrls?.length ? ctx.rpcUrls : (dep.default_rpc ? [dep.default_rpc] : []);
  if (urls.length === 0) fail(C.ANCHOR_NO_RPC, `no RPC configured for chain ${chainId}`);
  if (urls.length < ctx.policy.rpcQuorum) fail(C.RPC_QUORUM, `policy requires ${ctx.policy.rpcQuorum} independent RPCs, ${urls.length} configured`);
  const results = [];
  for (const url of urls) {
    try { results.push(await onOneRpc(url, { chainId, dep, ids: ctx.ids, signedTime: ctx.signedTime, ref, policy: ctx.policy, fetchImpl: ctx.fetchImpl, timeoutMs: ctx.timeoutMs })); }
    catch (e) { if (e instanceof KernelError) { e.detail = `${e.detail} [rpc ${results.length + 1}/${urls.length}]`; throw e; } throw new KernelError(C.RPC_ERROR, String(e?.message ?? e)); }
  }
  const fields = ['block_number', 'block_hash', 'time', 'observed_at', 'anchored_by', 'tx_hash', 'log_index'];
  for (const r of results.slice(1)) if (!sameFacts(results[0], r, fields)) fail(C.RPC_DISAGREEMENT, 'independent RPCs disagree on the anchor facts');
  const facts = { ...results[0], finalized: results.every((r) => r.finalized), rpc_count: results.length };
  facts.network_class = dep.network_class;
  facts.anchorer_known = (ctx.roots.known_anchorers?.evm || []).includes(facts.anchored_by);
  return facts;
}
