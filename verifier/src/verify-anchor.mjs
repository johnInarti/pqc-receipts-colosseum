#!/usr/bin/env node
/**
 * verify-anchor.mjs — compatibility layer over Trust Kernel v2 for anchored seals / MIDAS receipts.
 * The kernel decides everything: the anchor contract is PINNED by chain id (address + runtime code hash in
 * kernel/trust-roots.json), time comes from the block header, observedAt must equal the SIGNED time, keys are
 * trusted only through the pinned directory roots (or an explicit pinned key set = override).
 *
 * CLI:  x402-verify-anchor <seal.json> [--rpc URL]… [--cross-rpc URL]… [--finalized] [--keys-url URL]
 *         [--trusted-key B64]… [--allow-testnet] [--known-anchorer] [--anchored-by 0x…]
 * Exit code = first failed level (0 valid · 10 integrity · 11 authentic · 12 trusted · 13 time_anchored · 14 finalized).
 */
import { readFileSync } from 'node:fs';
import {
  verify, verifyDirectoryChain, keyAuthorizes, parseJsonStrict, boundedFetch, oneLine, safeJson, sha256hex,
  BAKED_ROOTS, RECEIPT_ANCHORED_TOPIC, ANCHOR_SCHEME, EXIT, KINDS,
} from '@fractalai/pqc-trust-kernel';

export { RECEIPT_ANCHORED_TOPIC, ANCHOR_SCHEME };
export const DEFAULT_KEYS_URL = 'https://fractalai.net.co/.well-known/x402-receipt-keys';
export const KNOWN_DEPLOYMENTS = Object.fromEntries(Object.entries(BAKED_ROOTS.anchors.evm).map(([k, d]) => [k, { address: d.contract, from_block: d.from_block, network: d.name, runtime_codehash: d.runtime_codehash }]));
export const PQC_ANCHOR_RUNTIME_CODEHASH = BAKED_ROOTS.anchors.evm['42161'].runtime_codehash;
export const DEFAULT_RPC_BY_CHAIN = Object.fromEntries(Object.entries(BAKED_ROOTS.anchors.evm).map(([k, d]) => [k, d.default_rpc]));

const sealMessage = (seal) => (seal.canonical !== undefined
  ? KINDS['midas-alert'].message(sha256hex(seal.canonical))
  : `${seal.domain}\n${seal.content_id}`);

/** The three bytes32 values a seal anchors to (informational; the kernel recomputes them from signed bytes). */
export function deriveAnchorIds(seal) {
  const sig = Buffer.from(seal.signature, 'base64');
  if (sig.length !== 3309) throw new Error(`ML-DSA-65 signature must be 3309 bytes, got ${sig.length}`);
  if (Buffer.from(seal.public_key, 'base64').length !== 1952) throw new Error('ML-DSA-65 public key must be 1952 bytes');
  const signedMessage = sealMessage(seal);
  return {
    receipt_id: '0x' + sha256hex(sig), payload_hash: '0x' + sha256hex(signedMessage),
    kid: '0x' + sha256hex(seal.public_key).slice(0, 16).padEnd(64, '0'), signed_message: signedMessage,
  };
}

/**
 * Keys usable NOW from a key directory — only if the directory verifies against the PINNED roots
 * (governance signature, root, checkpoint/anti-rollback). An unsigned or foreign directory yields [].
 * Prefer passing the whole directory to the kernel: it evaluates each key at the receipt's SIGNED time.
 */
export function trustedKeysFromDirectory(directory, nowSec = Math.floor(Date.now() / 1000)) {
  try {
    const dir = parseJsonStrict(typeof directory === 'string' ? directory : JSON.stringify(directory));
    const cp = BAKED_ROOTS.directory_checkpoint;
    const d = verifyDirectoryChain(dir, { governanceKeyB64: BAKED_ROOTS.governance.public_key_b64, checkpoint: { epoch: cp.epoch, root: cp.root } });
    return d.keys.filter((k) => keyAuthorizes(k, { uses: KINDS['midas-alert'].uses, signedTime: null, now: nowSec, anchorTime: null, skew: 0 }).ok).map((k) => k.public_key_b64);
  } catch {
    return [];
  }
}

function kindsFor(seal) {
  if (seal && typeof seal === 'object' && seal.canonical !== undefined) return ['midas-alert'];
  return ['x402-seal', 'self-attest-seal'];
}

/**
 * Verify an anchored seal or MIDAS receipt. Legacy options are mapped onto the kernel:
 *   trustedPublicKeysB64 → trustedKeys (override) · keyDirectory → directory (pinned roots)
 *   rpcUrl / crossCheckRpcUrls → per-chain RPC list (all must agree) · requireFinalized → policy
 *   minConfirmations → policy · expectedAnchoredBy → post-check on the consensus fact `anchored_by`
 *   contract → must equal the pinned deployment (an unpinned address is refused, never trusted)
 * Returns the legacy flat fields + `verdict` (the full leveled kernel verdict).
 */
export async function verifyAnchoredSeal(seal, opts = {}) {
  const refs = opts.anchor ? [opts.anchor] : Array.isArray(seal?.anchors) ? seal.anchors : seal?.anchor ? [seal.anchor] : [];
  const cleanRefs = refs.map((r) => (r && typeof r === 'object' ? { ...r, chain_id: Number(r.chain_id), ...(opts.contract ? { contract: opts.contract } : {}) } : r));
  const rpc = {};
  for (const r of cleanRefs) {
    if (!r || r.chain === 'solana') continue;
    const key = `eip155:${r.chain_id}`;
    const urls = [opts.rpcUrl ?? DEFAULT_RPC_BY_CHAIN[r.chain_id], ...(opts.crossCheckRpcUrls || [])].filter(Boolean);
    if (urls.length) rpc[key] = urls;
  }
  const { anchor, anchors, ...bare } = seal || {};
  const policy = { require: ['integrity', 'authentic', 'trusted', 'time_anchored', ...(opts.requireFinalized ? ['finalized'] : [])], minConfirmations: opts.minConfirmations ?? 1, allowTestnetAnchors: opts.allowTestnet === true };
  const k = { kinds: kindsFor(seal), checkAnchors: true, anchors: JSON.stringify(cleanRefs), rpc, policy, fetchImpl: opts.fetchImpl, now: opts.now };
  if (opts.trustedPublicKeysB64) k.trustedKeys = JSON.stringify(opts.trustedPublicKeysB64);
  if (opts.keyDirectory) k.directory = typeof opts.keyDirectory === 'string' ? opts.keyDirectory : JSON.stringify(opts.keyDirectory);
  let v;
  try { v = await verify(JSON.stringify(bare), k); } catch (e) { return { valid: false, reason: `verify error: ${e.message}` }; }
  const best = v.anchors.find((a) => a.counts) ?? v.anchors.find((a) => a.facts) ?? null;
  const f = best?.facts ?? {};
  let valid = v.valid;
  let reason = v.valid ? 'ok' : v.reasons.map((r) => `${r.code}: ${r.detail}`).join(' | ') || 'not valid';
  if (valid && opts.expectedAnchoredBy && String(f.anchored_by).toLowerCase() !== String(opts.expectedAnchoredBy).toLowerCase()) {
    valid = false; reason = `anchoredBy ${f.anchored_by} != expected ${opts.expectedAnchoredBy}`;
  }
  const noTrust = !opts.trustedPublicKeysB64 && !opts.keyDirectory;
  return {
    valid, signature_valid: v.levels.authentic, key_trusted: !v.levels.authentic ? false : noTrust ? null : v.levels.trusted,
    anchor_valid: v.levels.time_anchored === true,
    mode: v.kind === 'x402-seal' ? 'notary' : v.kind === 'self-attest-seal' ? 'self-attest' : v.kind ?? 'unknown',
    chain_id: f.chain ? Number(String(f.chain).split(':')[1]) : null, network_class: f.network_class ?? null,
    contract: f.contract ?? null, contract_known: !!f.contract && Object.values(BAKED_ROOTS.anchors.evm).some((d) => d.contract === f.contract), codehash_ok: !!f.contract,
    block_number: f.block_number ?? null, block_hash: f.block_hash ?? null,
    anchored_at: f.time ?? null, anchored_by: f.anchored_by ?? null, observed_at: f.observed_at ?? null,
    finalized: f.finalized ?? null, tx_hash: f.tx_hash ?? null, rpc_cross_checked: f.rpc_count ? f.rpc_count - 1 : 0,
    anchors_tried: v.anchors.length, reason, verdict: v,
  };
}

/** Fetch the raw key directory (bounded; strict JSON). The kernel verifies it against the pinned roots. */
export async function fetchKeyDirectory(url = DEFAULT_KEYS_URL, fetchImpl) {
  return parseJsonStrict(await boundedFetch(url, { headers: { accept: 'application/json' }, ...(fetchImpl ? { fetchImpl } : {}) }));
}
/** Keys usable now from the fetched directory (verified against the pinned roots; [] otherwise). */
export async function fetchTrustedKeys(url = DEFAULT_KEYS_URL, fetchImpl) {
  return trustedKeysFromDirectory(await fetchKeyDirectory(url, fetchImpl));
}

// ── CLI ───────────────────────────────────────────────────────────────────────────────────────
const isMain = typeof process !== 'undefined' && process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const args = process.argv.slice(2);
  const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
  const many = (n) => args.flatMap((a, i) => (a === n ? [args[i + 1]] : []));
  const file = args.find((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--') && !['--finalized', '--allow-testnet', '--known-anchorer'].includes(args[i - 1])));
  if (!file) { console.error('usage: x402-verify-anchor <seal.json> [--rpc URL] [--cross-rpc URL]… [--finalized] [--keys-url URL] [--trusted-key B64]…'); process.exit(EXIT.USAGE); }
  let raw;
  try { raw = parseJsonStrict(readFileSync(file, 'utf8')); } catch (e) { console.error(`error: ${oneLine(e.detail ?? e.message)}`); process.exit(EXIT.INPUT); }
  const seal = raw.seal && !raw.canonical && !raw.body ? { ...raw.seal, ...(raw.anchor && !raw.seal.anchor ? { anchor: raw.anchor } : {}) } : raw;
  const trusted = many('--trusted-key');
  const keyDirectory = trusted.length ? undefined : await boundedFetch(opt('--keys-url') ?? DEFAULT_KEYS_URL).catch((e) => { console.error(`error: key directory: ${oneLine(e.detail ?? e.message)}`); process.exit(EXIT.INPUT); });
  const r = await verifyAnchoredSeal(seal, {
    keyDirectory, trustedPublicKeysB64: trusted.length ? trusted : undefined, rpcUrl: opt('--rpc'), crossCheckRpcUrls: many('--cross-rpc'),
    requireFinalized: args.includes('--finalized'), allowTestnet: args.includes('--allow-testnet'), expectedAnchoredBy: opt('--anchored-by'),
  });
  const { verdict, ...flat } = r;
  console.log(safeJson(flat));
  process.exit(r.valid ? EXIT.VALID : (verdict?.exit_code || EXIT.time_anchored));
}
