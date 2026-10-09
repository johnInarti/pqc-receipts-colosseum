/**
 * Issuer of `latam-stablecoin-receipt` (spec/TRUST-KERNEL.md §12) — library.
 *
 * Given (chain id, tx hash[, log index]) of a payment that ALREADY happened, the issuer:
 *   1. reads the Transfer log from the chain on every configured RPC (same calls as the verifier, via the
 *      kernel's `observeEverywhere`) — amount, from, to, token, block are NEVER taken from the requester;
 *   2. refuses: reverted tx, log of a non-pinned contract, non-Transfer log, mint/burn, zero amount,
 *      token whose live symbol()/decimals() differ from the pinned registry, non-canonical block (reorg),
 *      too few confirmations, not finalized (unless explicitly allowed), RPC disagreement;
 *   3. builds the canonical, signs it with ML-DSA-65 under the stablecoin domain with the operator's key;
 *   4. self-verifies the result with the Trust Kernel (integrity + authentic + trusted-by-this-key + onchain)
 *      and only then returns it. A receipt the kernel would refuse is never emitted.
 *
 * The production signing key lives on the operator's server; this library never stores, logs or prints it.
 * Moves no funds, sends no transactions: JSON-RPC reads only.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  KernelError, CODES as C, verify, b64encode, b64decodeStrict, kidForKey, sha256hex, observeEverywhere, rpcCall,
  registryLookup, buildTransferCanonical, formatUnits, STABLECOIN_DOMAIN, TRANSFER_TOPIC, BAKED_STABLECOIN_REGISTRY,
  ML_DSA_65_PK_BYTES, parseJsonStrict,
} from '../../kernel/src/index.mjs';

const enc = (s) => new TextEncoder().encode(s);
const fail = (code, detail) => { throw new KernelError(code, detail); };
const ZERO = '0x' + '0'.repeat(40);

/**
 * Load an operator key. Accepted JSON shapes:
 *   { "algorithm": "ml-dsa-65", "seed_hex": "<64 hex>" }                       (32-byte FIPS 204 keygen seed)
 *   { "algorithm": "ml-dsa-65", "secret_key_b64": "…", "public_key_b64": "…" } (expanded key pair)
 * The pair is checked by a sign/verify round trip before use.
 */
export function loadKey(text) {
  const k = parseJsonStrict(text);
  if (!k || typeof k !== 'object' || k.algorithm !== 'ml-dsa-65') fail(C.INPUT_SHAPE, 'key file must be a JSON object with algorithm "ml-dsa-65"');
  let secretKey, publicKey;
  if (typeof k.seed_hex === 'string') {
    if (!/^[0-9a-f]{64}$/.test(k.seed_hex)) fail(C.INPUT_SHAPE, 'seed_hex must be 64 lowercase hex characters');
    const kp = ml_dsa65.keygen(Uint8Array.from(k.seed_hex.match(/../g), (x) => parseInt(x, 16)));
    secretKey = kp.secretKey; publicKey = kp.publicKey;
  } else if (typeof k.secret_key_b64 === 'string' && typeof k.public_key_b64 === 'string') {
    secretKey = b64decodeStrict(k.secret_key_b64, undefined, 'secret_key_b64');
    publicKey = b64decodeStrict(k.public_key_b64, ML_DSA_65_PK_BYTES, 'public_key_b64');
  } else fail(C.INPUT_SHAPE, 'key file needs seed_hex, or secret_key_b64 + public_key_b64');
  const probe = enc('fractalai-stablecoin-issuer key self-check');
  if (!ml_dsa65.verify(ml_dsa65.sign(probe, secretKey), probe, publicKey)) fail(C.INPUT_SHAPE, 'secret and public key do not form a pair');
  const publicKeyB64 = b64encode(publicKey);
  return Object.freeze({ secretKey, publicKeyB64, kid: kidForKey(publicKeyB64) });
}

/** Fresh random key (ephemeral / test use). Returns the JSON text of a seed key file. */
export function generateKeyFile() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  return JSON.stringify({ algorithm: 'ml-dsa-65', seed_hex: Array.from(seed, (b) => b.toString(16).padStart(2, '0')).join(''), note: 'EPHEMERAL TEST KEY - not listed in any FractalAI key directory' }, null, 2) + '\n';
}

/**
 * Sign already-validated transfer fields. NO chain reads: used by `issueStablecoinReceipt` after it has read
 * the chain, and by the corpus generator to model a compromised or buggy signer (negative vectors).
 */
export function signTransfer(fields, key, { deterministic = false } = {}) {
  const transfer_canonical = buildTransferCanonical(fields);
  const transfer_id = sha256hex(transfer_canonical);
  const signed_message = `${STABLECOIN_DOMAIN}\n${transfer_id}`;
  const signature = b64encode(ml_dsa65.sign(enc(signed_message), key.secretKey, deterministic ? { extraEntropy: false } : undefined));
  return {
    profile: 'latam-stablecoin-receipt', algorithm: 'ml-dsa-65', domain: STABLECOIN_DOMAIN,
    transfer_id, transfer_canonical, signed_message, transfer: { ...fields }, issued_at: Number(fields.issued_at),
    public_key: key.publicKeyB64, signature,
  };
}

/** Locate the single pinned-token Transfer log of a transaction when the caller gave no log index. */
async function locateLog(url, chainId, txHash, lookup, net) {
  const rc = await rpcCall(url, 'eth_getTransactionReceipt', [txHash], net);
  if (!rc || typeof rc !== 'object') fail(C.PAYMENT_TX_NOT_FOUND, `transaction ${txHash} not found on chain ${chainId}`);
  const cands = (Array.isArray(rc.logs) ? rc.logs : []).filter((l) => l && typeof l.address === 'string' && lookup.get(chainId, l.address.toLowerCase())
    && Array.isArray(l.topics) && String(l.topics[0]).toLowerCase() === TRANSFER_TOPIC);
  if (cands.length === 0) fail(C.TOKEN_NOT_PINNED, 'the transaction carries no Transfer of a pinned token');
  if (cands.length > 1) fail(C.INPUT_SHAPE, `the transaction carries ${cands.length} pinned-token Transfers; pass the log index`);
  return Number.parseInt(cands[0].logIndex, 16);
}

/**
 * @param {object} req
 *   chainId (number), txHash (0x…64), logIndex? (number), reference? ([A-Za-z0-9._:/-]{0,64}, an UNVERIFIED label),
 *   rpcUrls (string[], all must agree; default: the registry's default RPC), key (from loadKey),
 *   minConfirmations (default 1), requireFinalized (default true), rpcQuorum (default 1),
 *   registry (override of the pinned registry — tests only), now (unix s), maxClockSkewSec (default 900),
 *   deterministic (default false; corpus only), selfVerify (default true), fetchImpl, timeoutMs
 * @returns {Promise<{ receipt: object, text: string, facts: object, verdict: object|null }>}
 */
export async function issueStablecoinReceipt(req) {
  const {
    chainId, reference = '', key, minConfirmations = 1, requireFinalized = true, rpcQuorum = 1, registry,
    now = Math.floor(Date.now() / 1000), maxClockSkewSec = 900, deterministic = false, selfVerify = true, fetchImpl, timeoutMs,
  } = req;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) fail(C.INPUT_SHAPE, 'chainId must be a positive integer');
  if (typeof req.txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(req.txHash)) fail(C.INPUT_SHAPE, 'txHash must be 0x + 64 hex');
  const txHash = req.txHash.toLowerCase();
  if (req.logIndex !== undefined && !(Number.isSafeInteger(req.logIndex) && req.logIndex >= 0)) fail(C.INPUT_SHAPE, 'logIndex must be a non-negative integer');
  if (typeof reference !== 'string' || !/^[A-Za-z0-9._:/-]{0,64}$/.test(reference)) fail(C.INPUT_SHAPE, 'reference must match [A-Za-z0-9._:/-]{0,64}');
  if (!key || !key.secretKey || !key.publicKeyB64) fail(C.INPUT_SHAPE, 'an operator key (loadKey) is required');
  const lookup = registryLookup(registry);
  if (!lookup.chains?.[String(chainId)] && !req.rpcUrls?.length) fail(C.TOKEN_NOT_PINNED, `chain ${chainId} has no pinned stablecoin`);
  const urls = req.rpcUrls?.length ? req.rpcUrls : [lookup.chains[String(chainId)].default_rpc];
  const net = { fetchImpl, timeoutMs };
  const logIndex = req.logIndex ?? await locateLog(urls[0], chainId, txHash, lookup, net);

  const o = await observeEverywhere(urls, { chainId, txHash, logIndex, lookup }, { rpcQuorum }, net);
  const t = lookup.get(chainId, o.token);
  if (o.symbol !== t.symbol || o.decimals !== t.decimals) fail(C.TOKEN_METADATA_MISMATCH, `token now reports ${o.symbol}/${o.decimals}; pinned ${t.symbol}/${t.decimals} — refusing until the registry is reviewed`);
  if (o.from === ZERO || o.to === ZERO) fail(C.PAYMENT_NOT_A_TRANSFER, 'mint/burn (zero address) is not a payment between two parties');
  if (o.amount === '0') fail(C.PAYMENT_NOT_A_TRANSFER, 'zero-amount Transfer (typical of address-poisoning spam) is not a payment');
  if (o.confirmations < Math.max(1, minConfirmations)) fail(C.PAYMENT_CONFIRMATIONS, `${o.confirmations} confirmations < required ${minConfirmations}`);
  if (requireFinalized && !o.finalized) fail(C.PAYMENT_NOT_FINALIZED, 'the payment block is not finalized yet; retry later or pass requireFinalized:false');
  if (o.block_timestamp > now + maxClockSkewSec) fail(C.SIGNED_TIME_IN_FUTURE, `block time ${o.block_timestamp} is ahead of the issuer clock ${now}`);

  const fields = {
    registry: lookup.id, chain_id: String(chainId), token: o.token, token_symbol: t.symbol, token_decimals: String(t.decimals),
    from: o.from, to: o.to, amount: o.amount, amount_decimal: formatUnits(o.amount, t.decimals),
    tx_hash: txHash, log_index: String(logIndex), block_number: String(o.block_number), block_hash: o.block_hash,
    block_timestamp: String(o.block_timestamp), confirmations: String(o.confirmations), finality: o.finalized ? 'finalized' : 'confirmed',
    issued_at: String(Math.max(now, o.block_timestamp)), reference,
  };
  const receipt = signTransfer(fields, key, { deterministic });
  const text = JSON.stringify(receipt, null, 2) + '\n';
  let verdict = null;
  if (selfVerify) {
    verdict = await verify(text, {
      kind: 'latam-stablecoin-receipt', trustedKeys: JSON.stringify([key.publicKeyB64]), checkOnchain: true,
      rpc: { [`eip155:${chainId}`]: urls }, fetchImpl, timeoutMs, now: Number(fields.issued_at), ...(registry ? { tokenRegistry: JSON.stringify(registry) } : {}),
      policy: { require: ['integrity', 'authentic', 'trusted', 'onchain'], minConfirmations, rpcQuorum, allowUnfinalizedPayment: !requireFinalized },
    });
    if (!verdict.valid) fail(C.INTERNAL, `self-verification refused the receipt: ${JSON.stringify(verdict.reasons).slice(0, 400)}`);
  }
  return { receipt, text, facts: o, verdict };
}

export { BAKED_STABLECOIN_REGISTRY };
