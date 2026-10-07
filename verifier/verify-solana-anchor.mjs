#!/usr/bin/env node
// Verify a FractalAI receipt anchored on Solana via the SPL Memo program — from any public Solana RPC,
// with the ML-DSA-65 receipt signature checked locally. FAIL-CLOSED: exit 0 only on VALID.
//
// usage:
//   node verify-solana-anchor.mjs --record ../deployments/anchors/solana-devnet-fe62b072.json
//   node verify-solana-anchor.mjs --sig <base58 tx sig> --signer <announced pubkey> \
//        [--receipt fe62b072…|receipt.json] [--cluster devnet|mainnet-beta] [--rpc URL]
//        [--keys-url URL] [--no-key-pin]
//
// --record takes sig/signer/cluster from an anchor record (deployments/anchors/solana-*.json) and the
// receipt from that record's embedded seal; any explicit flag overrides it.
import { readFileSync, existsSync } from 'node:fs';
import { verifySolanaAnchor } from './src/solana-anchor.mjs';
import { fetchTrustedKeys, DEFAULT_KEYS_URL } from './src/verify-anchor.mjs';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const base = process.env.FRACTALAI_BASE || 'https://fractalai.net.co';

const record = opt('--record') ? JSON.parse(readFileSync(opt('--record'), 'utf8')) : null;
const signature = opt('--sig') ?? record?.anchor?.signature;
const expectedSigner = opt('--signer') ?? record?.anchor?.signer;
const cluster = opt('--cluster') ?? record?.anchor?.cluster ?? 'devnet';
if (!signature || !expectedSigner) {
  console.error('usage: node verify-solana-anchor.mjs (--record file.json | --sig SIG --signer PUBKEY) [--receipt ID|file.json] [--cluster devnet|mainnet-beta] [--rpc URL] [--keys-url URL] [--no-key-pin]');
  process.exit(2);
}

let receipt;
const rArg = opt('--receipt');
if (rArg && existsSync(rArg)) receipt = JSON.parse(readFileSync(rArg, 'utf8'));
else if (rArg) receipt = await (await fetch(`${base}/api/midas/alerts/receipt/${rArg}`, { signal: AbortSignal.timeout(20000) })).json();
else if (record?.seal) receipt = record.seal;
else receipt = await (await fetch(`${base}/api/midas/alerts/receipt/fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee`, { signal: AbortSignal.timeout(20000) })).json();

const trusted = args.includes('--no-key-pin') ? undefined : await fetchTrustedKeys(opt('--keys-url') ?? DEFAULT_KEYS_URL);
const result = await verifySolanaAnchor({ signature, receipt, expectedSigner, cluster, rpcUrl: opt('--rpc'), trustedPublicKeysB64: trusted });
console.log(JSON.stringify(result, null, 2));
console.log(result.valid ? `VALID — ${result.reason}` : `INVALID — ${result.reason}`);
process.exit(result.valid ? 0 : 1);
