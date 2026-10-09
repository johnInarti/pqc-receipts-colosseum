#!/usr/bin/env node
/**
 * Records the REAL public-RPC answers behind the latam-stablecoin-receipt vectors (spec §12) into
 * corpus/fixtures/stablecoin/, so the corpus replays real chain data offline and deterministically.
 * Each case runs the kernel's `observeTransfer` (exactly the calls the issuer and the verifier make) through
 * a recording transport. Read-only JSON-RPC; no keys, no transactions. Re-run only to refresh evidence:
 *   node corpus/record-stablecoins.mjs
 * The transfers were picked by eth_getLogs (Transfer topic, token address) on 2026-10-08, excluding mints,
 * burns and zero amounts, among blocks already reported `finalized` by the RPC.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { observeTransfer, registryLookup } from '../kernel/src/index.mjs';
import { recordingFetch } from './lib/replay.mjs';

const CASES = [
  { name: 'copm-polygon', chainId: 137, tx: '0x5cd84fa7d8e6a4fafc9783f7f0ced013225307a904d7bceb6923e7ac1777420b', logIndex: 2229, rpcs: [['https://polygon-bor-rpc.publicnode.com', 'replay://polygon'], ['https://1rpc.io/matic', 'replay://polygon-1rpc']] },
  { name: 'brla-polygon', chainId: 137, tx: '0x24f4d15425d46d121a2c488235de41677421ab74c3beee6882c87e18af44a387', logIndex: 593, rpcs: [['https://polygon-bor-rpc.publicnode.com', 'replay://polygon']] },
  { name: 'brla-base', chainId: 8453, tx: '0xb092820492bd011fd017564b934e00c4af354393185a3447a714954f52a6dd1e', logIndex: 1011, rpcs: [['https://mainnet.base.org', 'replay://base']] },
  { name: 'mxnb-arbitrum', chainId: 42161, tx: '0x54309433449ae3dec7bd76b002a8d8f138e19bac3cddfe13612a5c9a35e20f66', logIndex: 3, rpcs: [['https://arb1.arbitrum.io/rpc', 'replay://arb1'], ['https://1rpc.io/arb', 'replay://arb1-1rpc']] },
  { name: 'mxnb-base-swap', chainId: 8453, tx: '0x9963ad6af39fa13bf1efae916af0d561ea7f161bec77dae20aeb6ff4c914d4c8', logIndex: 22, rpcs: [['https://mainnet.base.org', 'replay://base']] },
];

const only = process.argv[2];
const dir = new URL('./fixtures/stablecoin/', import.meta.url);
mkdirSync(dir, { recursive: true });
const lookup = registryLookup();
for (const c of CASES) {
  if (only && c.name !== only) continue;
  const transcript = [], observed = [];
  for (const [url, label] of c.rpcs) {
    const rec = recordingFetch(() => label);
    const o = await observeTransfer(url, { chainId: c.chainId, txHash: c.tx, logIndex: c.logIndex, lookup }, { fetchImpl: rec.fetchImpl });
    transcript.push(...rec.transcript);
    observed.push({ rpc: label, source: url, ...o });
    console.log(`${c.name} via ${url}: ${o.symbol} ${o.amount} ${o.from} -> ${o.to} block ${o.block_number} conf ${o.confirmations} finalized ${o.finalized}`);
  }
  writeFileSync(new URL(`${c.name}.json`, dir), JSON.stringify({ recorded_at: new Date().toISOString(), chain_id: c.chainId, tx_hash: c.tx, log_index: c.logIndex, sources: c.rpcs.map(([u, l]) => ({ url: u, label: l })), observed, transcript }, null, 1) + '\n');
}
