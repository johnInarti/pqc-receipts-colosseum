/**
 * Kind `latam-stablecoin-receipt` (spec/TRUST-KERNEL.md §12): a post-quantum receipt for an ERC-20
 * Transfer of a PINNED Latin-American stablecoin that already happened on-chain.
 *
 *   signed message = "FRACTALAI-stablecoin-receipt-v1\n" + sha256hex(transfer_canonical)
 *   key use        = "stablecoin-receipt"  (never "x402-receipt": a key for one product cannot sign the other)
 *   signed time    = issued_at
 *
 * The canonical is a fixed, ordered list of `key=value` lines (no optional keys, no extras, lowercase hex,
 * canonical decimals). Integrity also checks the token against the pinned registry
 * (kernel/latam-stablecoins.json) and the decimal rendering of the amount.
 *
 * Level `onchain` (§12.4): every fact is recomputed from the chain — eth_chainId, the transaction receipt
 * (status, block, the log at log_index: emitter, Transfer topic, from/to/amount), the canonical header at
 * block_number (hash = signed block_hash, timestamp = signed block_timestamp), symbol()/decimals() of the
 * token, the head and the `finalized` block — independently on every configured RPC, which must agree.
 * `observeTransfer` is shared with the issuer (issuer/), so issuing and verifying make the same calls.
 */
import { C, KernelError, fail } from './codes.mjs';
import { sha256hex, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES } from './crypto.mjs';
import { b64decodeStrict, isPlainObject, own, toQty } from './hygiene.mjs';
import { rpcCall, sameFacts } from './rpc.mjs';
import { STABLECOIN_DOMAIN, USE } from './domains.mjs';
import registryJson from '../latam-stablecoins.json' with { type: 'json' };

export { STABLECOIN_DOMAIN };
export const STABLECOIN_CANON_HEADER = 'FRACTALAI-stablecoin-transfer-v1';
export const STABLECOIN_USE = USE.STABLECOIN;
export const REGISTRY_FORMAT = 'fractalai.stablecoin-registry/1';
export const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const SEL_SYMBOL = '0x95d89b41';
const SEL_DECIMALS = '0x313ce567';
const UINT256_MAX = (1n << 256n) - 1n;
const ZERO_ADDR = '0x' + '0'.repeat(40);

const DEC = /^(0|[1-9][0-9]{0,15})$/;
const ADDR = /^0x[0-9a-f]{40}$/;
const H32 = /^0x[0-9a-f]{64}$/;
/** Field order is normative. Each value: [regex, description]. */
export const TRANSFER_FIELDS = Object.freeze([
  ['registry', /^[a-z0-9][a-z0-9.-]{0,63}\/[1-9][0-9]{0,5}$/],
  ['chain_id', DEC],
  ['token', ADDR],
  ['token_symbol', /^[A-Za-z0-9.-]{1,16}$/],
  ['token_decimals', /^(0|[1-9][0-9]?)$/],
  ['from', ADDR],
  ['to', ADDR],
  ['amount', /^[1-9][0-9]{0,77}$/],
  ['amount_decimal', /^(0|[1-9][0-9]{0,77})(\.[0-9]{0,76}[1-9])?$/],
  ['tx_hash', H32],
  ['log_index', DEC],
  ['block_number', DEC],
  ['block_hash', H32],
  ['block_timestamp', DEC],
  ['confirmations', DEC],
  ['finality', /^(finalized|confirmed)$/],
  ['issued_at', DEC],
  ['reference', /^[A-Za-z0-9._:/-]{0,64}$/],
]);
const FIELD_NAMES = TRANSFER_FIELDS.map(([k]) => k);
const MAX_CANONICAL = 4096;

const deepFreeze = (o) => { if (o && typeof o === 'object') { Object.values(o).forEach(deepFreeze); Object.freeze(o); } return o; };

/** Structural check of a token registry (baked or caller-supplied). Returns a lookup. */
export function checkRegistry(reg) {
  const bad = (d) => fail(C.REGISTRY_INVALID, d);
  if (!isPlainObject(reg)) bad('registry is not an object');
  if (reg.format !== REGISTRY_FORMAT) bad(`registry format is not ${REGISTRY_FORMAT}`);
  if (typeof reg.id !== 'string' || !TRANSFER_FIELDS[0][1].test(reg.id)) bad('registry id malformed');
  if (!Array.isArray(reg.tokens) || reg.tokens.length === 0 || reg.tokens.length > 1024) bad('registry tokens[] missing, empty or > 1024');
  const chains = isPlainObject(reg.chains) ? reg.chains : {};
  const byKey = new Map();
  for (const t of reg.tokens) {
    if (!isPlainObject(t)) bad('token entry is not an object');
    if (!Number.isSafeInteger(t.chain_id) || t.chain_id <= 0) bad('token chain_id is not a positive integer');
    if (typeof t.address !== 'string' || !ADDR.test(t.address)) bad('token address must be lowercase 0x + 40 hex');
    if (typeof t.symbol !== 'string' || !TRANSFER_FIELDS[3][1].test(t.symbol)) bad(`token ${t.address} symbol malformed`);
    if (!Number.isSafeInteger(t.decimals) || t.decimals < 0 || t.decimals > 77) bad(`token ${t.address} decimals out of range`);
    const k = `${t.chain_id}:${t.address}`;
    if (byKey.has(k)) bad(`token ${k} listed twice`);
    byKey.set(k, t);
  }
  return { id: reg.id, chains, get: (chainId, address) => byKey.get(`${chainId}:${address}`) ?? null };
}
export const BAKED_STABLECOIN_REGISTRY = deepFreeze(registryJson);
const BAKED_LOOKUP = checkRegistry(BAKED_STABLECOIN_REGISTRY);
export const registryLookup = (reg) => (reg === undefined || reg === BAKED_STABLECOIN_REGISTRY ? BAKED_LOOKUP : checkRegistry(reg));

/** amount (integer string, smallest units) → canonical decimal string (no trailing zeros, no exponent). */
export function formatUnits(amount, decimals) {
  const s = BigInt(amount).toString();
  if (decimals === 0) return s;
  const p = s.padStart(decimals + 1, '0');
  const int = p.slice(0, p.length - decimals);
  const frac = p.slice(p.length - decimals).replace(/0+$/, '');
  return frac ? `${int}.${frac}` : int;
}

/** Build the canonical text from a field object (issuer side). Validates with the same rules as the parser. */
export function buildTransferCanonical(fields) {
  const lines = [STABLECOIN_CANON_HEADER];
  for (const k of FIELD_NAMES) {
    if (!own(fields, k)) fail(C.CANONICAL_MALFORMED, `transfer lacks ${k}`);
    lines.push(`${k}=${fields[k]}`);
  }
  for (const k of Object.keys(fields)) if (!FIELD_NAMES.includes(k)) fail(C.CANONICAL_MALFORMED, `unknown transfer field ${k}`);
  const canonical = lines.join('\n');
  parseTransferCanonical(canonical);
  return canonical;
}

/** Strict parser of the signed canonical: exact header, exact key order, every value matches its pattern. */
export function parseTransferCanonical(canonical) {
  if (typeof canonical !== 'string' || canonical.length === 0 || canonical.length > MAX_CANONICAL) fail(C.CANONICAL_MALFORMED, 'transfer_canonical missing or too long');
  const lines = canonical.split('\n');
  if (lines[0] !== STABLECOIN_CANON_HEADER) fail(C.CANONICAL_MALFORMED, `transfer_canonical header is not ${STABLECOIN_CANON_HEADER}`);
  if (lines.length !== TRANSFER_FIELDS.length + 1) fail(C.CANONICAL_MALFORMED, `transfer_canonical must have exactly ${TRANSFER_FIELDS.length} fields in the normative order`);
  const out = Object.create(null);
  TRANSFER_FIELDS.forEach(([k, re], i) => {
    const line = lines[i + 1];
    const eq = line.indexOf('=');
    if (eq < 0 || line.slice(0, eq) !== k) fail(C.CANONICAL_MALFORMED, `field ${i + 1} must be ${k}`);
    const v = line.slice(eq + 1);
    if (!re.test(v)) fail(C.CANONICAL_MALFORMED, `${k} value is malformed`);
    out[k] = v;
  });
  for (const k of ['chain_id', 'log_index', 'block_number', 'block_timestamp', 'confirmations', 'issued_at']) if (!Number.isSafeInteger(Number(out[k]))) fail(C.CANONICAL_MALFORMED, `${k} out of range`);
  if (BigInt(out.amount) > UINT256_MAX) fail(C.CANONICAL_MALFORMED, 'amount exceeds uint256');
  if (Number(out.chain_id) <= 0) fail(C.CANONICAL_MALFORMED, 'chain_id must be positive');
  if (Number(out.confirmations) < 1) fail(C.CANONICAL_MALFORMED, 'confirmations must be >= 1');
  if (Number(out.issued_at) < Number(out.block_timestamp)) fail(C.CANONICAL_MALFORMED, 'issued_at is before the block that carries the transfer');
  return out;
}

/** Semantic checks against the pinned registry (integrity level). */
export function checkTransferFacts(f, lookup) {
  if (f.registry !== lookup.id) fail(C.TOKEN_NOT_PINNED, `receipt names registry ${f.registry}, the pinned registry is ${lookup.id}`);
  const t = lookup.get(Number(f.chain_id), f.token);
  if (!t) fail(C.TOKEN_NOT_PINNED, `token ${f.token} on chain ${f.chain_id} is not in the pinned registry ${lookup.id}`);
  if (t.symbol !== f.token_symbol || String(t.decimals) !== f.token_decimals) fail(C.TOKEN_METADATA_MISMATCH, `signed ${f.token_symbol}/${f.token_decimals} != pinned ${t.symbol}/${t.decimals}`);
  if (formatUnits(f.amount, t.decimals) !== f.amount_decimal) fail(C.AMOUNT_FORMAT_MISMATCH, `amount_decimal ${f.amount_decimal} != amount ${f.amount} at ${t.decimals} decimals`);
  if (f.from === ZERO_ADDR || f.to === ZERO_ADDR) fail(C.PAYMENT_NOT_A_TRANSFER, 'mint/burn (zero address) is not a payment between two parties');
  return t;
}

/** Kind parser (called by kinds.mjs#parseReceipt). */
export function parseStablecoinReceipt(r, { tokenRegistry } = {}) {
  const known = new Set(['profile', 'algorithm', 'domain', 'transfer_canonical', 'transfer_id', 'signed_message', 'transfer', 'issued_at', 'public_key', 'signature']);
  if (own(r, 'algorithm') && r.algorithm !== 'ml-dsa-65') fail(C.ALGORITHM, `algorithm ${JSON.stringify(r.algorithm)} is not ml-dsa-65`);
  const lookup = registryLookup(tokenRegistry);
  const fields = parseTransferCanonical(r.transfer_canonical);
  const id = sha256hex(r.transfer_canonical);
  const message = `${STABLECOIN_DOMAIN}\n${id}`;
  if (own(r, 'domain') && r.domain !== STABLECOIN_DOMAIN) fail(C.DOMAIN_MISMATCH, `domain is not ${STABLECOIN_DOMAIN}`);
  if (own(r, 'transfer_id') && r.transfer_id !== id) fail(C.RECEIPT_ID_MISMATCH, 'transfer_id != sha256(transfer_canonical)');
  if (own(r, 'signed_message') && r.signed_message !== message) fail(C.SIGNED_MESSAGE_MISMATCH, 'signed_message != reconstructed signed message');
  const signedTime = Number(fields.issued_at);
  if (own(r, 'issued_at') && r.issued_at !== signedTime) fail(C.UNSIGNED_FIELD_MISMATCH, `top-level issued_at ${JSON.stringify(r.issued_at)} != signed issued_at ${signedTime}`);
  // The unsigned `transfer` copy: same keys, every value a STRING equal to the signed one. Numbers are
  // refused on purpose: a uint256 amount compared as an IEEE-754 double would let 1e21 "equal" 10^21+1 (A8).
  if (own(r, 'transfer')) {
    if (!isPlainObject(r.transfer)) fail(C.UNSIGNED_FIELD_MISMATCH, 'transfer is not an object');
    const bad = [];
    for (const k of Object.keys(r.transfer)) if (!own(fields, k) || typeof r.transfer[k] !== 'string' || r.transfer[k] !== fields[k]) bad.push(k);
    for (const k of FIELD_NAMES) if (!own(r.transfer, k)) bad.push(k);
    if (bad.length) fail(C.UNSIGNED_FIELD_MISMATCH, `transfer differs from the signed canonical: ${[...new Set(bad)].slice(0, 12).join(', ')}`);
  }
  checkTransferFacts(fields, lookup);
  return {
    kind: 'latam-stablecoin-receipt', content_id: id, message,
    pk: b64decodeStrict(r.public_key, ML_DSA_65_PK_BYTES, 'public_key'), sig: b64decodeStrict(r.signature, ML_DSA_65_SIG_BYTES, 'signature'), public_key_b64: r.public_key,
    signed_time: signedTime,
    signed: { transfer_id: id, canonical_header: STABLECOIN_CANON_HEADER, ...fields },
    ignored: Object.keys(r).filter((k) => !known.has(k) && k !== 'anchor' && k !== 'anchors'),
  };
}

// ───────────────────────────── on-chain observation (shared by issuer and verifier) ─────────────────────────────
const lc = (s) => String(s).toLowerCase();
const malformed = (d) => new KernelError(C.PAYMENT_RPC_MALFORMED, d);
function pqty(h, what) {
  if (typeof h !== 'string' || !/^0x[0-9a-fA-F]{1,16}$/.test(h)) throw malformed(`${what} is not a hex quantity`);
  const v = Number.parseInt(h.slice(2), 16);
  if (!Number.isSafeInteger(v)) throw malformed(`${what} out of range`);
  return v;
}
const isH32 = (s) => typeof s === 'string' && /^0x[0-9a-fA-F]{64}$/.test(s);

/** Strict ABI decoding of `string` return data (offset 0x20, length, zero padding). */
export function abiDecodeString(hex) {
  if (typeof hex !== 'string' || !/^0x([0-9a-fA-F]{64})+$/.test(hex)) fail(C.PAYMENT_TOKEN_METADATA, 'symbol() did not return ABI words');
  const d = hex.slice(2).toLowerCase();
  if (BigInt('0x' + d.slice(0, 64)) !== 32n) fail(C.PAYMENT_TOKEN_METADATA, 'symbol() is not an ABI dynamic string');
  const len = BigInt('0x' + d.slice(64, 128));
  if (len > 64n) fail(C.PAYMENT_TOKEN_METADATA, 'symbol() string too long');
  const n = Number(len), words = Math.ceil(n / 32);
  if (d.length !== 128 + words * 64) fail(C.PAYMENT_TOKEN_METADATA, 'symbol() return has trailing or missing words');
  const body = d.slice(128, 128 + n * 2);
  if (!/^0*$/.test(d.slice(128 + n * 2))) fail(C.PAYMENT_TOKEN_METADATA, 'symbol() padding is not zero');
  const bytes = Uint8Array.from(body.match(/../g) || [], (x) => parseInt(x, 16));
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { return fail(C.PAYMENT_TOKEN_METADATA, 'symbol() is not UTF-8'); }
}
export function abiDecodeUint8(hex) {
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(hex)) fail(C.PAYMENT_TOKEN_METADATA, 'decimals() did not return one ABI word');
  const v = BigInt(hex);
  if (v > 255n) fail(C.PAYMENT_TOKEN_METADATA, 'decimals() out of uint8 range');
  return Number(v);
}

/**
 * One RPC, one observation of the Transfer log at (tx_hash, log_index). Fixed call list (spec §12.4):
 * eth_chainId · eth_getTransactionReceipt · eth_getBlockByNumber(n,false) · eth_call symbol() · eth_call decimals()
 * · eth_blockNumber · eth_getBlockByNumber("finalized",false).
 * @param {object} q  { chainId, txHash, logIndex, token?: expected emitter (verifier), lookup?: registry (issuer) }
 */
export async function observeTransfer(url, q, { fetchImpl, timeoutMs } = {}) {
  const call = (m, p) => rpcCall(url, m, p, { fetchImpl, timeoutMs });
  const live = pqty(await call('eth_chainId', []), 'eth_chainId');
  if (live !== q.chainId) fail(C.PAYMENT_WRONG_CHAIN, `RPC serves chain ${live}, the payment is on chain ${q.chainId}`);
  const rc = await call('eth_getTransactionReceipt', [q.txHash]);
  if (rc === null || rc === undefined) fail(C.PAYMENT_TX_NOT_FOUND, `transaction ${q.txHash} not found on chain ${q.chainId}`);
  if (!isPlainObject(rc)) throw malformed('transaction receipt is not an object');
  if (rc.status !== '0x1') {
    if (rc.status === '0x0') fail(C.PAYMENT_TX_REVERTED, 'the transaction reverted (status 0x0): no transfer happened');
    throw malformed('receipt status is neither 0x1 nor 0x0');
  }
  if (lc(rc.transactionHash) !== q.txHash) throw malformed('receipt transactionHash differs from the requested one');
  if (!isH32(rc.blockHash)) throw malformed('receipt has no blockHash');
  const blockNumber = pqty(rc.blockNumber, 'receipt.blockNumber');
  const blockHash = lc(rc.blockHash);
  const logs = Array.isArray(rc.logs) ? rc.logs : [];
  const at = logs.filter((l) => isPlainObject(l) && pqty(l.logIndex, 'log.logIndex') === q.logIndex);
  if (at.length === 0) fail(C.PAYMENT_LOG_NOT_FOUND, `transaction has no log with index ${q.logIndex}`);
  if (at.length > 1) throw malformed(`several logs carry index ${q.logIndex}`);
  const log = at[0];
  if (log.removed === true) fail(C.PAYMENT_LOG_REMOVED, 'the log was removed by a reorg');
  if (lc(log.blockHash) !== blockHash || pqty(log.blockNumber, 'log.blockNumber') !== blockNumber || lc(log.transactionHash) !== q.txHash) throw malformed('log block/tx fields disagree with the receipt');
  if (typeof log.address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(log.address)) throw malformed('log address malformed');
  const emitter = lc(log.address);
  if (q.token !== undefined && emitter !== q.token) fail(C.PAYMENT_LOG_WRONG_CONTRACT, `log ${q.logIndex} was emitted by ${emitter}, not by the token ${q.token}`);
  if (q.token === undefined && !q.lookup.get(q.chainId, emitter)) fail(C.TOKEN_NOT_PINNED, `log ${q.logIndex} was emitted by ${emitter}, which is not a pinned token on chain ${q.chainId}`);
  const tp = log.topics;
  if (!Array.isArray(tp) || tp.length !== 3 || lc(tp[0]) !== TRANSFER_TOPIC || !tp.slice(1).every((t) => typeof t === 'string' && /^0x0{24}[0-9a-fA-F]{40}$/.test(t))) fail(C.PAYMENT_LOG_NOT_TRANSFER, 'log is not an ERC-20 Transfer(address,address,uint256) event');
  if (typeof log.data !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(log.data)) fail(C.PAYMENT_LOG_NOT_TRANSFER, 'Transfer data is not exactly one uint256');
  const from = '0x' + lc(tp[1]).slice(26), to = '0x' + lc(tp[2]).slice(26), amount = BigInt(log.data).toString();

  const blk = await call('eth_getBlockByNumber', [toQty(blockNumber), false]);
  if (!isPlainObject(blk)) fail(C.PAYMENT_REORGED, `block ${blockNumber} not found`);
  if (pqty(blk.number, 'block.number') !== blockNumber) throw malformed('header number mismatch');
  if (lc(blk.hash) !== blockHash) fail(C.PAYMENT_REORGED, `the receipt's block ${blockHash} is not the canonical block ${lc(blk.hash)} at height ${blockNumber}`);
  const time = pqty(blk.timestamp, 'block.timestamp');

  const symbol = abiDecodeString(await call('eth_call', [{ to: emitter, data: SEL_SYMBOL }, 'latest']));
  const decimals = abiDecodeUint8(await call('eth_call', [{ to: emitter, data: SEL_DECIMALS }, 'latest']));
  const head = pqty(await call('eth_blockNumber', []), 'eth_blockNumber');
  let finalized = false;
  try {
    const f = await call('eth_getBlockByNumber', ['finalized', false]);
    finalized = isPlainObject(f) && pqty(f.number, 'finalized.number') >= blockNumber;
  } catch { finalized = false; }
  return {
    chain_id: q.chainId, token: emitter, from, to, amount, tx_hash: q.txHash, log_index: q.logIndex,
    block_number: blockNumber, block_hash: blockHash, block_timestamp: time, symbol, decimals,
    head, confirmations: head - blockNumber + 1, finalized,
  };
}
export const AGREEMENT_FIELDS = ['chain_id', 'token', 'from', 'to', 'amount', 'tx_hash', 'log_index', 'block_number', 'block_hash', 'block_timestamp', 'symbol', 'decimals'];

/** Run `observeTransfer` on every URL; all must succeed and agree (spec §7.4 applied to payments). */
export async function observeEverywhere(urls, q, policy, net) {
  if (!urls || urls.length === 0) fail(C.PAYMENT_NO_RPC, `no RPC configured for chain ${q.chainId}`);
  if (urls.length < policy.rpcQuorum) fail(C.RPC_QUORUM, `policy requires ${policy.rpcQuorum} independent RPCs, ${urls.length} configured`);
  const results = [];
  for (const url of urls) {
    try { results.push(await observeTransfer(url, q, net)); }
    catch (e) { if (e instanceof KernelError) { e.detail = `${e.detail} [rpc ${results.length + 1}/${urls.length}]`; throw e; } throw new KernelError(C.RPC_ERROR, String(e?.message ?? e)); }
  }
  for (const r of results.slice(1)) if (!sameFacts(results[0], r, AGREEMENT_FIELDS)) fail(C.RPC_DISAGREEMENT, 'independent RPCs disagree on the transfer facts');
  return { ...results[0], confirmations: Math.min(...results.map((r) => r.confirmations)), finalized: results.every((r) => r.finalized), rpc_count: results.length };
}

/**
 * Verifier side (level `onchain`): recompute and compare with the SIGNED fields.
 * @param {object} s     signed projection (strings, as in the canonical)
 * @param {object} ctx   { rpcUrls, policy, fetchImpl, timeoutMs, lookup }
 */
export async function verifyStablecoinPayment(s, ctx) {
  const chainId = Number(s.chain_id);
  const urls = ctx.rpcUrls?.length ? ctx.rpcUrls : (ctx.lookup.chains?.[s.chain_id]?.default_rpc ? [ctx.lookup.chains[s.chain_id].default_rpc] : []);
  const o = await observeEverywhere(urls, { chainId, txHash: s.tx_hash, logIndex: Number(s.log_index), token: s.token }, ctx.policy, { fetchImpl: ctx.fetchImpl, timeoutMs: ctx.timeoutMs });
  if (o.block_number !== Number(s.block_number)) fail(C.PAYMENT_BLOCK_MISMATCH, `the transaction is in block ${o.block_number}, the receipt says ${s.block_number}`);
  if (o.block_hash !== s.block_hash) fail(C.PAYMENT_REORGED, `signed block_hash ${s.block_hash} is no longer the canonical block of this transaction (${o.block_hash})`);
  if (o.block_timestamp !== Number(s.block_timestamp)) fail(C.PAYMENT_TIME_MISMATCH, `header timestamp ${o.block_timestamp} != signed block_timestamp ${s.block_timestamp}`);
  if (o.from !== s.from || o.to !== s.to) fail(C.PAYMENT_PARTY_MISMATCH, `on-chain ${o.from} -> ${o.to} differs from the signed parties`);
  if (o.amount !== s.amount) fail(C.PAYMENT_AMOUNT_MISMATCH, `on-chain amount ${o.amount} != signed amount ${s.amount}`);
  if (o.symbol !== s.token_symbol || String(o.decimals) !== s.token_decimals) fail(C.PAYMENT_TOKEN_METADATA, `token now reports ${o.symbol}/${o.decimals}, signed ${s.token_symbol}/${s.token_decimals}`);
  const need = Math.max(1, ctx.policy.minConfirmations);
  if (o.confirmations < need) fail(C.PAYMENT_CONFIRMATIONS, `${o.confirmations} confirmations < policy ${need}`);
  if (o.confirmations < Number(s.confirmations)) fail(C.PAYMENT_CONFIRMATIONS, `chain shows ${o.confirmations} confirmations, fewer than the ${s.confirmations} the signer claimed (RPC behind, or the claim is false)`);
  if (s.finality === 'finalized' && !o.finalized) fail(C.PAYMENT_NOT_FINALIZED, 'the signer claimed finality but the chain does not report the block as finalized');
  if (!o.finalized && !ctx.policy.allowUnfinalizedPayment) fail(C.PAYMENT_NOT_FINALIZED, 'the payment block is not finalized yet (policy.allowUnfinalizedPayment is false)');
  return o;
}
