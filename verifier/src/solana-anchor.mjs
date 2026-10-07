/**
 * solana-anchor.mjs — anchor a FractalAI ML-DSA-65-signed receipt on Solana with the SPL Memo program,
 * and verify such an anchor from any public Solana RPC. Zero Solana SDK: base58, the legacy transaction
 * wire format and Ed25519 (node:crypto) are implemented here in ~200 auditable lines.
 *
 * Scheme `fractalai.pqc-receipt-anchor/1` (same ids as the EVM PQCReceiptAnchor):
 *   receipt_id   = sha256(ML-DSA-65 signature bytes)
 *   payload_hash = sha256(utf8(`${domain}\n${content_id}`))   — the exact bytes the ML-DSA-65 signature covers
 *   kid          = sha256(public_key_b64)[:16 hex]              — the 8-byte key id (left part of the EVM bytes32)
 *   observed_at  = issuer-claimed emission time (unix seconds)
 * Canonical memo (UTF-8, no whitespace, lowercase hex without 0x):
 *   fractalai.pqc-receipt-anchor/1|rid=<64 hex>|ph=<64 hex>|kid=<16 hex>|obs=<decimal>
 *
 * What the anchor proves: a transaction signed by the announced Solana key carried exactly these bytes and
 * reached `finalized` at a given slot/time — existence-by-time. The Memo program checks NOTHING about the
 * receipt; the ML-DSA-65 signature is verified off-chain by verifySolanaAnchor().
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const ANCHOR_SCHEME = 'fractalai.pqc-receipt-anchor/1';
export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const MIDAS_DOMAIN = 'FRACTALAI-x402-served-v1\nmidas-alert';
export const DEFAULT_RPC = {
  devnet: 'https://api.devnet.solana.com',
  'mainnet-beta': 'https://api.mainnet-beta.solana.com',
};
export const explorerTx = (sig, cluster) =>
  `https://explorer.solana.com/tx/${sig}${cluster === 'mainnet-beta' ? '' : `?cluster=${cluster}`}`;

const sha256hex = (d) => createHash('sha256').update(d).digest('hex');

// ── base58 (Bitcoin alphabet) ────────────────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function b58encode(bytes) {
  const b = Uint8Array.from(bytes);
  let n = 0n;
  for (const x of b) n = n * 256n + BigInt(x);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x !== 0) break; s = '1' + s; }
  return s;
}
export function b58decode(str) {
  if (typeof str !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]+$/.test(str)) throw new Error('invalid base58');
  let n = 0n;
  for (const c of str) n = n * 58n + BigInt(B58.indexOf(c));
  const out = [];
  while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of str) { if (c !== '1') break; out.unshift(0); }
  return Uint8Array.from(out);
}

// ── keys ─────────────────────────────────────────────────────────────────────────────────────
/** Solana CLI keypair file format: JSON array of 64 bytes = seed(32) || pubkey(32). */
export function keypairFromSolanaJson(arr) {
  if (!Array.isArray(arr) || arr.length !== 64) throw new Error('keypair must be a 64-byte JSON array');
  const raw = Uint8Array.from(arr);
  const seed = raw.slice(0, 32), pub = raw.slice(32);
  const privateKey = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: Buffer.from(seed).toString('base64url'), x: Buffer.from(pub).toString('base64url') }, format: 'jwk' });
  // Refuse a file whose public half does not match its seed.
  const derived = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url');
  if (!derived.equals(Buffer.from(pub))) throw new Error('keypair file: public key does not match seed');
  return { publicKey: pub, privateKey, pubkey: b58encode(pub) };
}
const edPublicKey = (pub32) => createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pub32).toString('base64url') }, format: 'jwk' });

// ── receipt → anchor ids → memo ──────────────────────────────────────────────────────────────
/**
 * Normalise a MIDAS alert receipt (public API shape: receipt_id, canonical, served_domain, served_message,
 * public_key, signature, emitted_at) or an anchor-record seal (domain, content_id, canonical, …) into a seal.
 * Throws on internal inconsistency.
 */
export function sealFromReceipt(r) {
  if (!r || typeof r !== 'object') throw new Error('receipt is not an object');
  const s = r.seal ?? r;
  if (s.algorithm !== 'ml-dsa-65') throw new Error(`unsupported algorithm '${s.algorithm}'`);
  // API shape: `domain` is the canonical-text domain (FRACTALAI-midas-alert-v1); the SIGNED domain is `served_domain`.
  const domain = s.served_domain ?? s.domain;
  const content_id = s.content_id ?? s.receipt_id;
  if (typeof s.canonical !== 'string') throw new Error('receipt has no canonical text');
  if (sha256hex(Buffer.from(s.canonical, 'utf8')) !== content_id) throw new Error('content_id != sha256(canonical) — receipt body altered');
  if (s.served_message !== undefined && s.served_message !== `${domain}\n${content_id}`) throw new Error('served_message != domain\\ncontent_id');
  const emitted_at = Number(s.emitted_at);
  if (!Number.isSafeInteger(emitted_at) || emitted_at <= 0) throw new Error('emitted_at missing or not an integer');
  return { algorithm: 'ml-dsa-65', domain, content_id, public_key: s.public_key, signature: s.signature, canonical: s.canonical, emitted_at };
}

export function deriveAnchorIds(seal) {
  const sig = Buffer.from(seal.signature, 'base64');
  if (sig.length !== 3309) throw new Error(`ML-DSA-65 signature must be 3309 bytes, got ${sig.length}`);
  const pk = Buffer.from(seal.public_key, 'base64');
  if (pk.length !== 1952) throw new Error(`ML-DSA-65 public key must be 1952 bytes, got ${pk.length}`);
  const signed_message = `${seal.domain}\n${seal.content_id}`;
  return {
    receipt_id: sha256hex(sig),
    payload_hash: sha256hex(Buffer.from(signed_message, 'utf8')),
    kid: sha256hex(seal.public_key).slice(0, 16),
    observed_at: Number(seal.emitted_at),
    signed_message,
  };
}

export function buildMemo(ids) {
  return `${ANCHOR_SCHEME}|rid=${ids.receipt_id}|ph=${ids.payload_hash}|kid=${ids.kid}|obs=${ids.observed_at}`;
}

/** Offline ML-DSA-65 check of the seal. `trustedPublicKeysB64` omitted → keyTrusted:null (integrity only). */
export function verifyReceiptSignature(seal, trustedPublicKeysB64) {
  if (seal.domain !== MIDAS_DOMAIN) return { ok: false, keyTrusted: false, reason: `unexpected domain '${seal.domain}'` };
  const sigOk = ml_dsa65.verify(Buffer.from(seal.signature, 'base64'), Buffer.from(`${seal.domain}\n${seal.content_id}`, 'utf8'), Buffer.from(seal.public_key, 'base64')) === true;
  if (!sigOk) return { ok: false, keyTrusted: false, reason: 'ML-DSA-65 signature does not verify' };
  if (!trustedPublicKeysB64) return { ok: true, keyTrusted: null, reason: 'ok' };
  const keyTrusted = trustedPublicKeysB64.includes(seal.public_key);
  return { ok: keyTrusted, keyTrusted, reason: keyTrusted ? 'ok' : 'signature valid but key not in trusted set' };
}

// ── legacy transaction wire format ───────────────────────────────────────────────────────────
function shortvec(n) {
  const out = [];
  for (;;) { let b = n & 0x7f; n >>= 7; if (n === 0) { out.push(b); return out; } out.push(b | 0x80); }
}
function readShortvec(buf, off) {
  let n = 0, shift = 0;
  for (let i = 0; i < 3; i++) {
    const b = buf[off.i++];
    if (b === undefined) throw new Error('truncated shortvec');
    n |= (b & 0x7f) << shift; shift += 7;
    if ((b & 0x80) === 0) return n;
  }
  throw new Error('shortvec too long');
}

/**
 * One-instruction legacy message: Memo(data = memo, accounts = [fee payer as signer]).
 * Account keys: [payer (signer, writable), memo program (readonly, unsigned)].
 */
export function buildMemoMessage({ payer32, recentBlockhash, memo, programId = MEMO_PROGRAM_ID }) {
  const program = b58decode(programId);
  const bh = b58decode(recentBlockhash);
  if (payer32.length !== 32 || program.length !== 32 || bh.length !== 32) throw new Error('bad key/blockhash length');
  const data = Buffer.from(memo, 'utf8');
  return Buffer.from([
    1, 0, 1,                              // header: 1 signer, 0 readonly-signed, 1 readonly-unsigned
    ...shortvec(2), ...payer32, ...program,
    ...bh,
    ...shortvec(1),                       // 1 instruction
    1, ...shortvec(1), 0,                 // program index 1, accounts [0]
    ...shortvec(data.length), ...data,
  ]);
}

export function signTransaction(message, privateKey) {
  const sig = edSign(null, message, privateKey);
  return { signature: b58encode(sig), wire: Buffer.concat([Buffer.from(shortvec(1)), sig, message]) };
}

/** Parse a legacy or v0 wire transaction (v0 lookups are reported but never resolved → caller rejects). */
export function parseTransaction(wire) {
  const buf = Uint8Array.from(wire);
  const off = { i: 0 };
  const nsig = readShortvec(buf, off);
  const signatures = [];
  for (let k = 0; k < nsig; k++) { signatures.push(buf.slice(off.i, off.i + 64)); off.i += 64; }
  const message = buf.slice(off.i);
  let version = 'legacy';
  if (buf[off.i] & 0x80) { version = buf[off.i] & 0x7f; off.i++; }
  const header = { numRequiredSignatures: buf[off.i++], numReadonlySigned: buf[off.i++], numReadonlyUnsigned: buf[off.i++] };
  const nkeys = readShortvec(buf, off);
  const accountKeys = [];
  for (let k = 0; k < nkeys; k++) { accountKeys.push(buf.slice(off.i, off.i + 32)); off.i += 32; }
  const recentBlockhash = buf.slice(off.i, off.i + 32); off.i += 32;
  const nix = readShortvec(buf, off);
  const instructions = [];
  for (let k = 0; k < nix; k++) {
    const programIdIndex = buf[off.i++];
    const na = readShortvec(buf, off);
    const accounts = Array.from(buf.slice(off.i, off.i + na)); off.i += na;
    const nd = readShortvec(buf, off);
    const data = buf.slice(off.i, off.i + nd); off.i += nd;
    instructions.push({ programIdIndex, accounts, data });
  }
  let addressTableLookups = 0;
  if (version !== 'legacy') addressTableLookups = readShortvec(buf, off);
  if (version === 'legacy' && off.i !== buf.length) throw new Error('trailing bytes after legacy message');
  if (signatures.length !== header.numRequiredSignatures) throw new Error('signature count != header.numRequiredSignatures');
  return { signatures, message, version, header, accountKeys, recentBlockhash, instructions, addressTableLookups };
}

// ── RPC ──────────────────────────────────────────────────────────────────────────────────────
export async function rpc(url, method, params, fetchImpl = fetch, timeoutMs = 20000) {
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

// ── verification ─────────────────────────────────────────────────────────────────────────────
/**
 * FAIL-CLOSED verification of a Solana Memo anchor.
 * @param {object} p
 * @param {string} p.signature           base58 tx signature
 * @param {object} p.receipt             MIDAS receipt (API shape) or anchor-record seal
 * @param {string} p.expectedSigner      announced anchoring pubkey (base58) — REQUIRED
 * @param {string} [p.cluster]           'devnet' | 'mainnet-beta' (default devnet)
 * @param {string} [p.rpcUrl]
 * @param {string[]} [p.trustedPublicKeysB64]  issuer ML-DSA-65 keys; omit → integrity only, valid stays true but key_trusted:null
 * @param {Function} [p.fetchImpl]
 */
export async function verifySolanaAnchor(p) {
  const out = {
    valid: false, scheme: ANCHOR_SCHEME, cluster: p.cluster ?? 'devnet', signature: p.signature ?? null,
    signature_valid: false, key_trusted: null, tx_found: false, tx_finalized: false, tx_error: null,
    ed25519_valid: false, signer: null, program: null, memo_matches: false, slot: null, block_time: null,
    expected_memo: null, onchain_memo: null, reason: '',
  };
  try {
    const fetchImpl = p.fetchImpl ?? fetch;
    if (typeof p.expectedSigner !== 'string' || b58decode(p.expectedSigner).length !== 32) { out.reason = 'expectedSigner (announced pubkey) missing or not a 32-byte base58 key'; return out; }
    let sigBytes;
    try { sigBytes = b58decode(p.signature); } catch { sigBytes = new Uint8Array(); }
    if (sigBytes.length !== 64) { out.reason = 'tx signature is not 64-byte base58'; return out; }

    // 1) Receipt: integrity + ML-DSA-65, offline.
    const seal = sealFromReceipt(p.receipt);
    const sv = verifyReceiptSignature(seal, p.trustedPublicKeysB64);
    out.key_trusted = sv.keyTrusted;
    out.signature_valid = sv.reason === 'ok' || sv.reason === 'signature valid but key not in trusted set';
    if (!sv.ok) { out.reason = `receipt: ${sv.reason}`; return out; }
    const expectedMemo = buildMemo(deriveAnchorIds(seal));
    out.expected_memo = expectedMemo;

    // 2) Transaction at `finalized` commitment (null otherwise).
    const rpcUrl = p.rpcUrl ?? DEFAULT_RPC[out.cluster];
    if (!rpcUrl) { out.reason = `no default RPC for cluster '${out.cluster}'; pass rpcUrl`; return out; }
    const tx = await rpc(rpcUrl, 'getTransaction', [p.signature, { encoding: 'base64', commitment: 'finalized', maxSupportedTransactionVersion: 0 }], fetchImpl);
    if (!tx) { out.reason = 'tx not found at finalized commitment (wrong cluster, pending, or pruned)'; return out; }
    out.tx_found = true; out.slot = tx.slot ?? null; out.block_time = tx.blockTime ?? null;
    if (!tx.meta) { out.reason = 'tx has no meta'; return out; }
    if (tx.meta.err !== null) { out.tx_error = tx.meta.err; out.reason = `tx failed on-chain: ${JSON.stringify(tx.meta.err)}`; return out; }
    // getTransaction(commitment:finalized) only returns finalized txs; double-check with the status API.
    const st = await rpc(rpcUrl, 'getSignatureStatuses', [[p.signature], { searchTransactionHistory: true }], fetchImpl);
    const s0 = st?.value?.[0];
    if (!s0 || s0.confirmationStatus !== 'finalized' || s0.err !== null) { out.reason = `signature status is not finalized/ok (${s0 ? s0.confirmationStatus : 'null'})`; return out; }
    out.tx_finalized = true;

    // 3) Raw bytes: parse, check the Ed25519 signature ourselves (do not trust the RPC on who signed).
    const wire = Buffer.from(Array.isArray(tx.transaction) ? tx.transaction[0] : tx.transaction, 'base64');
    const t = parseTransaction(wire);
    if (!Buffer.from(t.signatures[0]).equals(Buffer.from(sigBytes))) { out.reason = 'RPC returned a tx whose first signature differs from the one requested'; return out; }
    if (t.addressTableLookups) { out.reason = 'address lookup tables not accepted in an anchor tx'; return out; }
    const payer = t.accountKeys[0];
    out.signer = b58encode(payer);
    if (!edVerify(null, Buffer.from(t.message), edPublicKey(payer), Buffer.from(t.signatures[0]))) { out.reason = 'Ed25519 signature over the message does not verify'; return out; }
    out.ed25519_valid = true;
    if (out.signer !== p.expectedSigner) { out.reason = `signer ${out.signer} != announced ${p.expectedSigner}`; return out; }

    // 4) Exactly one instruction, to the Memo program, memo bytes identical to the recomputed one.
    if (t.instructions.length !== 1) { out.reason = `anchor tx must carry exactly 1 instruction, has ${t.instructions.length}`; return out; }
    const ix = t.instructions[0];
    const programKey = t.accountKeys[ix.programIdIndex];
    out.program = programKey ? b58encode(programKey) : null;
    if (out.program !== MEMO_PROGRAM_ID) { out.reason = `instruction program ${out.program} is not SPL Memo ${MEMO_PROGRAM_ID}`; return out; }
    if (!ix.accounts.includes(0)) { out.reason = 'memo instruction does not list the announced signer as a signing account'; return out; }
    out.onchain_memo = Buffer.from(ix.data).toString('utf8');
    if (!Buffer.from(ix.data).equals(Buffer.from(expectedMemo, 'utf8'))) { out.reason = 'on-chain memo is not byte-identical to the memo recomputed from the receipt'; return out; }
    out.memo_matches = true;

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
