/**
 * solana-anchor.mjs — issuer tooling to anchor a FractalAI ML-DSA-65 receipt with the SPL Memo program
 * (keypair loading, legacy message building, Ed25519 signing) + a compatibility `verifySolanaAnchor`
 * that DELEGATES the whole decision to Trust Kernel v2 (genesis pinning, finalized + blockTime required,
 * local Ed25519, announced signer, exactly one Memo v2 instruction, memo rebuilt from the SIGNED receipt).
 *
 * Scheme fractalai.pqc-receipt-anchor/1 (same ids as the EVM PQCReceiptAnchor):
 *   fractalai.pqc-receipt-anchor/1|rid=<sha256(sig)>|ph=<sha256(signed message)>|kid=<16 hex>|obs=<SIGNED emitted_at>
 */
import { createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import {
  verify, keyAuthorizes, b58encode, b58decode, buildMemo as kernelBuildMemo, parseTransaction, shortvec, parseReceipt, anchorIds,
  parseJsonStrict, BAKED_ROOTS, ANCHOR_SCHEME, MEMO_PROGRAM_ID, KINDS,
} from '@fractalai/pqc-trust-kernel';

export { b58encode, b58decode, parseTransaction, ANCHOR_SCHEME, MEMO_PROGRAM_ID };
export const MIDAS_DOMAIN = KINDS['midas-alert'].domain;
export const GENESIS_HASH = Object.fromEntries(Object.entries(BAKED_ROOTS.anchors.solana.clusters).map(([k, c]) => [k, c.genesis_hash]));
export const DEFAULT_RPC = Object.fromEntries(Object.entries(BAKED_ROOTS.anchors.solana.clusters).map(([k, c]) => [k, c.default_rpc]));
export const TEST_CLUSTERS = new Set(Object.entries(BAKED_ROOTS.anchors.solana.clusters).filter(([, c]) => c.network_class !== 'production').map(([k]) => k));
export const explorerTx = (sig, cluster) => `https://explorer.solana.com/tx/${sig}${cluster === 'mainnet-beta' ? '' : `?cluster=${cluster}`}`;

/** Solana CLI keypair file: JSON array of 64 bytes = seed(32) || pubkey(32). Refuses a mismatched file. */
export function keypairFromSolanaJson(arr) {
  if (!Array.isArray(arr) || arr.length !== 64) throw new Error('keypair must be a 64-byte JSON array');
  const raw = Uint8Array.from(arr);
  const seed = raw.slice(0, 32), pub = raw.slice(32);
  const privateKey = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: Buffer.from(seed).toString('base64url'), x: Buffer.from(pub).toString('base64url') }, format: 'jwk' });
  const derived = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url');
  if (!derived.equals(Buffer.from(pub))) throw new Error('keypair file: public key does not match seed');
  return { publicKey: pub, privateKey, pubkey: b58encode(pub) };
}

/**
 * Normalise a MIDAS receipt (API shape or anchor-record seal) through the kernel's strict parser:
 * every unsigned duplicate (emitted_at, facts, served_message, snapshot…) must match the signed bytes.
 * Returns the fields the anchor needs; `emitted_at` is ALWAYS the signed value.
 */
export function sealFromReceipt(r) {
  const s = r?.seal ?? r;
  const { anchor, anchors, ...bare } = s || {};
  const p = parseReceipt(parseJsonStrict(JSON.stringify(bare)), 'midas-alert');
  return { algorithm: 'ml-dsa-65', domain: MIDAS_DOMAIN, content_id: p.content_id, public_key: p.public_key_b64, signature: s.signature, canonical: s.canonical, emitted_at: p.signed_time, _parsed: p };
}

export function deriveAnchorIds(seal) {
  const p = seal._parsed ?? sealFromReceipt(seal)._parsed;
  const ids = anchorIds(p);
  return { receipt_id: ids.receipt_id, payload_hash: ids.payload_hash, kid: ids.kid16, observed_at: p.signed_time, signed_message: p.message };
}

export const buildMemo = (ids) => kernelBuildMemo({ receipt_id: ids.receipt_id, payload_hash: ids.payload_hash, kid16: ids.kid ?? ids.kid16, observed_at: ids.observed_at });

/** One-instruction legacy message: Memo(data = memo, accounts = [fee payer as signer]). */
export function buildMemoMessage({ payer32, recentBlockhash, memo, programId = MEMO_PROGRAM_ID }) {
  const program = b58decode(programId, 32);
  const bh = b58decode(recentBlockhash, 32);
  if (payer32.length !== 32) throw new Error('bad payer key length');
  const data = Buffer.from(memo, 'utf8');
  return Buffer.from([1, 0, 1, ...shortvec(2), ...payer32, ...program, ...bh, ...shortvec(1), 1, ...shortvec(1), 0, ...shortvec(data.length), ...data]);
}

export function signTransaction(message, privateKey) {
  const sig = edSign(null, message, privateKey);
  return { signature: b58encode(sig), wire: Buffer.concat([Buffer.from(shortvec(1)), sig, message]) };
}

/**
 * Compatibility wrapper → kernel. `expectedSigner` is honoured as an explicit announced-signer OVERRIDE
 * (reflected in verdict.overrides) unless it already is an announced signer in the pinned roots.
 * trustedPublicKeysB64 → trustedKeys (override); keyDirectory → directory (pinned roots).
 */
export async function verifySolanaAnchor(p) {
  const cluster = p.cluster ?? 'devnet';
  const announced = BAKED_ROOTS.anchors.solana.announced_signers?.[cluster] || [];
  const k = {
    kind: 'midas-alert', checkAnchors: true, anchors: JSON.stringify([{ chain: 'solana', cluster, signature: p.signature }]),
    rpc: { [`solana:${cluster}`]: [p.rpcUrl ?? DEFAULT_RPC[cluster], ...(p.crossCheckRpcUrls || [])].filter(Boolean) },
    policy: { require: ['integrity', 'authentic', 'trusted', 'time_anchored'], allowTestnetAnchors: true }, fetchImpl: p.fetchImpl, now: p.now,
  };
  if (p.expectedSigner && !announced.includes(p.expectedSigner)) k.solanaSigners = [p.expectedSigner];
  if (p.trustedPublicKeysB64) k.trustedKeys = JSON.stringify(p.trustedPublicKeysB64);
  if (p.keyDirectory) k.directory = typeof p.keyDirectory === 'string' ? p.keyDirectory : JSON.stringify(p.keyDirectory);
  const rr = p.receipt?.seal ?? p.receipt;
  const { anchor, anchors, ...bare } = rr || {};
  const v = await verify(JSON.stringify(bare), k);
  const a = v.anchors[0];
  const f = a?.facts ?? {};
  const noTrust = !p.trustedPublicKeysB64 && !p.keyDirectory;
  return {
    valid: v.valid, scheme: ANCHOR_SCHEME, cluster, network_class: f.network_class ?? (TEST_CLUSTERS.has(cluster) ? 'test' : 'production'), signature: p.signature ?? null,
    signature_valid: v.levels.authentic, key_trusted: !v.levels.authentic ? false : noTrust ? null : v.levels.trusted,
    tx_found: !!a?.ok, tx_finalized: f.finalized === true, signer: f.signer ?? null, program: a?.ok ? MEMO_PROGRAM_ID : null,
    memo_matches: !!a?.ok, slot: f.slot ?? null, block_time: f.time ?? null, expected_memo: f.memo ?? null,
    rpc_cross_checked: f.rpc_count ? f.rpc_count - 1 : 0,
    reason: v.valid ? (v.kind && f.network_class === 'test' ? `ok (${cluster} is a TEST cluster — not a durable public timestamp)` : 'ok') : v.reasons.map((r) => `${r.code}: ${r.detail}`).join(' | '),
    verdict: v,
  };
}

/**
 * Compatibility helper: is `publicKeyB64` authorized by an ALREADY VERIFIED directory's entry at anchor time
 * `t`? Delegates to the kernel lifecycle (revoked keys only with revoked_at > t, since `t` is a consensus time).
 * It does NOT verify the directory — use the kernel (`verify` with `directory`) for that.
 */
export function keyTrustedAt(directory, publicKeyB64, t) {
  const k = (Array.isArray(directory?.keys) ? directory.keys : []).find((x) => x?.public_key_b64 === publicKeyB64);
  if (!k) return { trusted: false, reason: 'key not listed in the directory' };
  const a = keyAuthorizes({ use: 'x402-receipt', ...k }, { uses: KINDS['midas-alert'].uses, signedTime: t, now: t, anchorTime: t - 1, skew: 0 });
  return { trusted: a.ok, reason: a.ok ? 'ok' : `${a.code}: ${a.detail}` };
}
