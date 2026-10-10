#!/usr/bin/env node
// Verify a FractalAI receipt anchored on Solana via the SPL Memo program — decided by Trust Kernel v2
// (pinned genesis hash, finalized + blockTime required, local Ed25519, announced signer, exactly one Memo v2
// instruction, memo rebuilt byte-for-byte from the SIGNED receipt). Devnet/testnet are marked "test".
//
// usage:
//   node verify-solana-anchor.mjs --record ../deployments/anchors/solana-devnet-fe62b072.json
//   node verify-solana-anchor.mjs --sig <base58 tx sig> [--receipt receipt.json] [--cluster devnet|mainnet-beta]
//        [--rpc URL] [--cross-rpc URL]… [--signer PUBKEY (override)] [--keys-url URL] [--trusted-key B64]…
// exit: 0 valid · 10–13 first failed level · 2 usage · 3 input
import { readFileSync } from 'node:fs';
import { boundedFetch, fetchLegacyDirectory, parseJsonStrict, oneLine, safeJson, EXIT } from '@fractalai/pqc-trust-kernel';
import { verifySolanaAnchor } from './src/solana-anchor.mjs';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const many = (n) => args.flatMap((a, i) => (a === n ? [args[i + 1]] : []));
const DEFAULT_KEYS = 'https://fractalai.net.co/.well-known/x402-receipt-keys';
const read = (p) => parseJsonStrict(readFileSync(p, 'utf8'));

try {
  const record = opt('--record') ? read(opt('--record')) : null;
  const signature = opt('--sig') ?? record?.anchor?.signature;
  const cluster = opt('--cluster') ?? record?.anchor?.cluster ?? 'devnet';
  const receipt = opt('--receipt') ? read(opt('--receipt')) : record?.seal;
  if (!signature || !receipt) { console.error('usage: node verify-solana-anchor.mjs (--record file.json | --sig SIG --receipt receipt.json) [--cluster C] [--rpc URL]'); process.exit(EXIT.USAGE); }
  const trusted = many('--trusted-key');
  const keyDirectory = trusted.length ? undefined : (await fetchLegacyDirectory(opt('--keys-url') ?? DEFAULT_KEYS)).text;
  const r = await verifySolanaAnchor({
    signature, receipt, cluster, rpcUrl: opt('--rpc'), crossCheckRpcUrls: many('--cross-rpc'), expectedSigner: opt('--signer'),
    keyDirectory, trustedPublicKeysB64: trusted.length ? trusted : undefined,
  });
  const { verdict, ...flat } = r;
  console.log(safeJson(flat));
  console.log(r.valid ? `VALID — ${oneLine(r.reason)}` : `INVALID — ${oneLine(r.reason, 400)}`);
  process.exit(r.valid ? EXIT.VALID : verdict.exit_code || EXIT.time_anchored);
} catch (e) {
  console.error(`error: ${oneLine(e.detail ?? e.message)}`);
  process.exit(EXIT.INPUT);
}
