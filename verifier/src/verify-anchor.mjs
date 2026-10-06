/**
 * verify-anchor.mjs — OFFLINE + ANY-RPC verification of an Arbitrum-anchored, ML-DSA-65-signed x402 seal.
 * Nothing here talks to FractalAI: the signature is checked locally with @noble/post-quantum against
 * public keys you pin (or fetch once from the public key directory), and the anchor is checked against
 * any Arbitrum JSON-RPC endpoint of YOUR choosing.
 *
 * On-chain record (PQCReceiptAnchor.ReceiptAnchored, write-once per receiptId):
 *   receiptId   = sha256(ML-DSA-65 signature bytes)
 *   payloadHash = sha256(utf8(`${seal.domain}\n${seal.content_id}`))  — the exact bytes the signature covers
 *   kid         = sha256(public_key_b64)[:16] (8 bytes) left-aligned in bytes32
 *
 * Verdict is FAIL-CLOSED: `valid` is true only when the signature verifies over the recomputed content_id,
 * the key is in the trust list (when one is given), the chain id matches, and the on-chain event for the
 * recomputed receiptId carries the same payloadHash and kid. Every negative path returns a `reason`.
 *
 * CLI:  node src/verify-anchor.mjs <seal.json> [--rpc https://sepolia-rollup.arbitrum.io/rpc]
 *         [--contract 0x…] [--keys-url https://fractalai.net.co/.well-known/x402-receipt-keys] [--no-key-pin]
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifySeal } from './witness-core.mjs';

export const ANCHOR_SCHEME = 'fractalai.pqc-receipt-anchor/1';
/** keccak256("ReceiptAnchored(bytes32,bytes32,bytes32,uint64,address,uint256)") */
export const RECEIPT_ANCHORED_TOPIC = '0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184';
export const DEFAULT_RPC_BY_CHAIN = {
  421614: 'https://sepolia-rollup.arbitrum.io/rpc',
  42161: 'https://arb1.arbitrum.io/rpc',
};
export const DEFAULT_KEYS_URL = 'https://fractalai.net.co/.well-known/x402-receipt-keys';

const sha256hex = (data) => createHash('sha256').update(data).digest('hex');

/** Pure: the three bytes32 values a seal anchors to. Throws on non-ML-DSA-65 sizes. */
export function deriveAnchorIds(seal) {
  const sig = Buffer.from(seal.signature, 'base64');
  if (sig.length !== 3309) throw new Error(`ML-DSA-65 signature must be 3309 bytes, got ${sig.length}`);
  const pk = Buffer.from(seal.public_key, 'base64');
  if (pk.length !== 1952) throw new Error(`ML-DSA-65 public key must be 1952 bytes, got ${pk.length}`);
  const signedMessage = `${seal.domain}\n${seal.content_id}`;
  return {
    receipt_id: '0x' + sha256hex(sig),
    payload_hash: '0x' + sha256hex(Buffer.from(signedMessage, 'utf8')),
    kid: '0x' + sha256hex(seal.public_key).slice(0, 16).padEnd(64, '0'),
    signed_message: signedMessage,
  };
}

async function rpc(url, method, params, fetchImpl, timeoutMs = 15000) {
  const res = await fetchImpl(url, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`rpc ${method} HTTP ${res.status}`);
  const j = await res.json();
  if (j.error) throw new Error(`rpc ${method}: ${j.error.message || JSON.stringify(j.error)}`);
  return j.result;
}

const hexToInt = (h) => (typeof h === 'string' ? parseInt(h, 16) : Number(h));
const lc = (s) => String(s || '').toLowerCase();

/**
 * Keys accepted from a FractalAI-style key directory: `active` and `retiring` (not yet past not_after),
 * plus legacy epoch-1 entries without lifecycle fields. `revoked`/`reserved` never verify receipts.
 */
export function trustedKeysFromDirectory(directory, nowSec = Math.floor(Date.now() / 1000)) {
  const keys = Array.isArray(directory?.keys) ? directory.keys : [];
  return keys.filter((k) => {
    if (typeof k?.public_key_b64 !== 'string') return false;
    if (k.status === undefined) return true; // epoch-1 historical shape
    if (k.status !== 'active' && k.status !== 'retiring') return false;
    if (typeof k.not_after === 'number' && nowSec > k.not_after) return false;
    return true;
  }).map((k) => k.public_key_b64);
}

/**
 * Verify a seal that carries `seal.anchor` (or pass `opts.anchor`).
 *
 * @param {object} seal  { algorithm, domain, content_id, public_key, signature, body, anchor? }
 * @param {object} [opts]
 * @param {string[]} [opts.trustedPublicKeysB64]  pin the issuer's keys; omit → keyTrusted:null (integrity only)
 * @param {string}   [opts.rpcUrl]                any JSON-RPC for the anchor's chain (default by chain_id)
 * @param {string}   [opts.contract]              expected PQCReceiptAnchor address (default: seal.anchor.contract)
 * @param {string}   [opts.expectedAnchoredBy]    optionally pin the anchoring EOA
 * @param {object}   [opts.anchor]                anchor reference if not embedded in the seal
 * @param {Function} [opts.fetchImpl]
 * @param {number}   [opts.minConfirmations]      default 1 (Arbitrum L2 blocks; L1 finality is a separate matter)
 */
export async function verifyAnchoredSeal(seal, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const out = {
    valid: false, signature_valid: false, key_trusted: null, anchor_valid: false,
    mode: 'unknown', chain_id: null, block_number: null, anchored_at: null, anchored_by: null, tx_hash: null,
    receipt_id: null, payload_hash: null, kid: null, reason: '',
  };
  try {
    // 1) Signature + integrity, fully offline.
    const sv = verifySeal(seal, { trustedPublicKeysB64: opts.trustedPublicKeysB64 });
    out.mode = sv.mode; out.key_trusted = sv.keyTrusted;
    out.signature_valid = sv.valid || sv.reason === 'signature valid but key not trusted';
    if (!sv.valid) { out.reason = `seal: ${sv.reason}`; return out; }

    // 2) Recompute what MUST be on-chain.
    const ids = deriveAnchorIds(seal);
    out.receipt_id = ids.receipt_id; out.payload_hash = ids.payload_hash; out.kid = ids.kid;

    const anchor = opts.anchor ?? seal.anchor;
    if (!anchor || typeof anchor !== 'object') { out.reason = 'no anchor reference (seal.anchor missing) — signature valid, nothing anchored'; return out; }
    if (anchor.scheme && anchor.scheme !== ANCHOR_SCHEME) { out.reason = `unknown anchor scheme '${anchor.scheme}'`; return out; }
    const contract = lc(opts.contract ?? anchor.contract);
    if (!/^0x[0-9a-f]{40}$/.test(contract)) { out.reason = 'anchor.contract is not an address'; return out; }
    const chainId = Number(anchor.chain_id);
    out.chain_id = chainId;
    const rpcUrl = opts.rpcUrl ?? DEFAULT_RPC_BY_CHAIN[chainId];
    if (!rpcUrl) { out.reason = `no RPC known for chain ${chainId}; pass rpcUrl`; return out; }

    // The anchor reference's own claims must match what we recomputed (cheap local check first).
    if (anchor.receipt_id && lc(anchor.receipt_id) !== ids.receipt_id) { out.reason = 'anchor.receipt_id != sha256(signature)'; return out; }
    if (anchor.payload_hash && lc(anchor.payload_hash) !== ids.payload_hash) { out.reason = 'anchor.payload_hash != sha256(signed bytes)'; return out; }

    // 3) Chain id — refuse to read a log from the wrong network.
    const liveChain = hexToInt(await rpc(rpcUrl, 'eth_chainId', [], fetchImpl));
    if (liveChain !== chainId) { out.reason = `rpc chain id ${liveChain} != anchor.chain_id ${chainId}`; return out; }

    // 4) Locate the event: by tx hash + log index when known, else by receiptId topic over the contract.
    let log = null;
    if (typeof anchor.tx_hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(anchor.tx_hash)) {
      const rcpt = await rpc(rpcUrl, 'eth_getTransactionReceipt', [anchor.tx_hash], fetchImpl);
      if (!rcpt) { out.reason = `tx ${anchor.tx_hash} not found (pending or wrong chain)`; return out; }
      if (hexToInt(rcpt.status) !== 1) { out.reason = `tx ${anchor.tx_hash} reverted`; return out; }
      const logs = Array.isArray(rcpt.logs) ? rcpt.logs : [];
      const candidates = logs.filter((l) => lc(l.address) === contract && lc(l.topics?.[0]) === RECEIPT_ANCHORED_TOPIC && lc(l.topics?.[1]) === ids.receipt_id);
      if (typeof anchor.log_index === 'number') {
        log = candidates.find((l) => hexToInt(l.logIndex) === anchor.log_index) ?? null;
        if (!log) { out.reason = `tx ${anchor.tx_hash} has no ReceiptAnchored(receiptId) log at log_index ${anchor.log_index}`; return out; }
      } else {
        log = candidates[0] ?? null;
        if (!log) { out.reason = `tx ${anchor.tx_hash} contains no ReceiptAnchored log for this receiptId`; return out; }
      }
      out.tx_hash = anchor.tx_hash;
    } else {
      const logs = await rpc(rpcUrl, 'eth_getLogs', [{ address: contract, topics: [RECEIPT_ANCHORED_TOPIC, ids.receipt_id], fromBlock: '0x0', toBlock: 'latest' }], fetchImpl);
      if (!Array.isArray(logs) || logs.length === 0) { out.reason = 'no ReceiptAnchored event for this receiptId on the contract'; return out; }
      if (logs.length > 1) { out.reason = 'multiple ReceiptAnchored events for one receiptId — contract invariant broken, refusing'; return out; }
      log = logs[0]; out.tx_hash = log.transactionHash ?? null;
    }

    // 5) The on-chain record must match the recomputed values exactly.
    if (lc(log.topics[2]) !== ids.payload_hash) { out.reason = 'on-chain payloadHash != sha256(signed bytes) — anchored bytes differ from this seal'; return out; }
    if (lc(log.topics[3]) !== ids.kid) { out.reason = 'on-chain kid != sha256(public_key)[:16] — anchored under a different key id'; return out; }
    const data = String(log.data || '0x').slice(2);
    if (data.length < 192) { out.reason = 'malformed event data'; return out; }
    const observedAt = parseInt(data.slice(0, 64), 16);
    const anchoredBy = '0x' + data.slice(64 + 24, 128);
    const anchoredAt = parseInt(data.slice(128, 192), 16);
    out.anchored_by = anchoredBy; out.anchored_at = anchoredAt; out.block_number = hexToInt(log.blockNumber);
    if (opts.expectedAnchoredBy && lc(opts.expectedAnchoredBy) !== lc(anchoredBy)) { out.reason = `anchoredBy ${anchoredBy} != expected ${opts.expectedAnchoredBy}`; return out; }
    if (Number.isFinite(observedAt) && observedAt > anchoredAt + 15 * 60) { out.reason = 'observedAt after anchoredAt beyond skew — inconsistent'; return out; }

    // 6) Confirmation depth (L2 blocks).
    const minConf = opts.minConfirmations ?? 1;
    if (minConf > 0) {
      const head = hexToInt(await rpc(rpcUrl, 'eth_blockNumber', [], fetchImpl));
      if (head - out.block_number + 1 < minConf) { out.reason = `only ${head - out.block_number + 1} confirmations (< ${minConf})`; return out; }
    }

    out.anchor_valid = true;
    out.valid = true;
    out.reason = out.key_trusted === null
      ? 'ok (signature + anchor verified; NO key pin supplied — integrity proven, issuer identity NOT authenticated)'
      : 'ok';
    return out;
  } catch (e) {
    out.reason = `${e?.constructor?.name ?? 'Error'}: ${e?.message ?? String(e)}`;
    return out;
  }
}

/** Fetch the public key directory and return the currently-acceptable receipt keys. */
export async function fetchTrustedKeys(url = DEFAULT_KEYS_URL, fetchImpl = fetch) {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`key directory HTTP ${res.status}`);
  return trustedKeysFromDirectory(await res.json());
}

// ── CLI ───────────────────────────────────────────────────────────────────────────────────────
const isMain = typeof process !== 'undefined' && process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const args = process.argv.slice(2);
  const file = args.find((a) => !a.startsWith('--'));
  const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  if (!file) {
    console.error('usage: node verify-anchor.mjs <seal.json> [--rpc URL] [--contract 0x…] [--keys-url URL] [--no-key-pin] [--anchored-by 0x…]');
    process.exit(2);
  }
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const seal = raw.seal ?? raw; // accept the full /api/x402/witness response or the bare seal
  const trusted = args.includes('--no-key-pin') ? undefined : await fetchTrustedKeys(opt('--keys-url') ?? DEFAULT_KEYS_URL);
  const result = await verifyAnchoredSeal(seal, { trustedPublicKeysB64: trusted, rpcUrl: opt('--rpc'), contract: opt('--contract'), expectedAnchoredBy: opt('--anchored-by') });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid ? 0 : 1);
}
