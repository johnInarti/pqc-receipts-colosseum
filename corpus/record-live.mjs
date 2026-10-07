#!/usr/bin/env node
/**
 * Records the REAL public-RPC answers behind the live positive anchors into corpus/fixtures/transcripts,
 * so the corpus replays real chain data offline and deterministically. Re-run only to refresh evidence:
 *   node corpus/record-live.mjs
 * Reads only public data (receipt API, key directory, Arc / Arbitrum One / Solana devnet RPCs). No keys.
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { verify, boundedFetch, parseJsonStrict } from '../kernel/src/index.mjs';
import { recordingFetch } from './lib/replay.mjs';

const F = (p) => new URL(`./fixtures/${p}`, import.meta.url);
const ID = 'fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee';
const receipt = await boundedFetch(`https://fractalai.net.co/api/midas/alerts/receipt/${ID}`);
const directory = await boundedFetch('https://fractalai.net.co/.well-known/x402-receipt-keys');
writeFileSync(F('midas-fe62b072.json'), JSON.stringify(parseJsonStrict(receipt), null, 2) + '\n');
writeFileSync(F('directory-epoch3.json'), JSON.stringify(parseJsonStrict(directory), null, 2) + '\n');
for (const f of ['PQCReceiptAnchor-5042-fe62b072.json', 'solana-devnet-fe62b072.json']) {
  writeFileSync(F(f), readFileSync(new URL(`../deployments/anchors/${f}`, import.meta.url), 'utf8'));
}
const LABEL = { 'https://rpc.mainnet.arc.io': 'replay://arc', 'https://arb1.arbitrum.io/rpc': 'replay://arb1', 'https://api.devnet.solana.com': 'replay://sol-devnet' };
const runs = {
  'arc-tx': { ref: { chain_id: 5042, tx_hash: '0x31979b7fa0a6605ea4ac9380051c92ad6b6e222fc39ada10ea46e655eab86b64', log_index: 5 }, rpc: { 'eip155:5042': ['https://rpc.mainnet.arc.io'] } },
  'arc-logs': { ref: { chain_id: 5042, block_number: 24072596 }, rpc: { 'eip155:5042': ['https://rpc.mainnet.arc.io'] } },
  'arb1-tx': { ref: { chain_id: 42161, tx_hash: '0x37f0254389deed3953aa44333e32eaeb466f28ff41ac9299eb5285599a7a1174', log_index: 5 }, rpc: { 'eip155:42161': ['https://arb1.arbitrum.io/rpc'] } },
  'arb1-logs': { ref: { chain_id: 42161, block_number: 511335916 }, rpc: { 'eip155:42161': ['https://arb1.arbitrum.io/rpc'] } },
  'sol-devnet': { ref: { chain: 'solana', cluster: 'devnet', signature: '5U5CQn94ix6Unbjk5ixKoRfyqmQ8HiPttwyssmUdoGdyCQzupnvNgKL3znnqN46UWLoWuhYHqaiFyynro6pP3qXi' }, rpc: { 'solana:devnet': ['https://api.devnet.solana.com'] } },
};
for (const [name, r] of Object.entries(runs)) {
  const rec = recordingFetch((u) => LABEL[u] ?? u);
  const v = await verify(receipt, { kind: 'midas-alert', directory, checkAnchors: true, anchors: JSON.stringify([r.ref]), rpc: r.rpc, fetchImpl: rec.fetchImpl, policy: { allowTestnetAnchors: true } });
  if (!v.levels.time_anchored) throw new Error(`${name}: live anchor did not verify: ${JSON.stringify(v.reasons)}`);
  writeFileSync(F(`transcripts/${name}.json`), JSON.stringify({ recorded_at: new Date().toISOString(), ref: r.ref, transcript: rec.transcript }, null, 1) + '\n');
  console.log(`${name}: ${rec.transcript.length} calls recorded, anchor time ${v.anchors[0].facts.time}, finalized ${v.anchors[0].facts.finalized}`);
}
