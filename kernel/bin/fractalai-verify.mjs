#!/usr/bin/env node
/**
 * fractalai-verify — Trust Kernel v2 CLI. Exit code = first REQUIRED level that failed:
 *   0 valid · 10 integrity · 11 authentic · 12 trusted · 13 time_anchored · 14 finalized · 15 onchain · 2 usage · 3 input/network
 *
 *   fractalai-verify <receipt.json | 64-hex receipt id | https URL> [options]
 *     --kind K                 expected kind (default midas-alert; repeatable: x402-seal, served-proof, acp-verdict, self-attest-seal,
 *                              latam-stablecoin-receipt)
 *     --onchain                recompute the payment facts from the chain (latam-stablecoin-receipt; level `onchain`)
 *     --allow-unfinalized-payment   accept a payment block that is confirmed but not yet finalized
 *     --token-registry FILE    OVERRIDE of the pinned stablecoin registry (reported in `overrides`)
 *     --directory URL|FILE     key directory (default: the public FractalAI directory, verified against the PINNED roots)
 *     --history FILE           an intermediate directory epoch (repeatable) for epoch-chain verification
 *     --anchors                verify time anchors (receipt.anchor / receipt.anchors, or --anchor-ref FILE)
 *     --anchor-ref FILE        JSON anchor reference or array of references (hints only)
 *     --rpc CHAIN=URL          RPC for eip155:<id> or solana:<cluster> (repeatable; several URLs = cross-check)
 *     --require L1,L2          levels required for "valid" (default integrity,authentic,trusted)
 *     --allow-testnet          count devnet/testnet anchors as time proofs (they stay marked "test")
 *     --known-anchorer         require the EVM anchorer to be a known FractalAI address
 *     --min-confirmations N    --quorum N    --now UNIX    --json
 *   Overrides (reflected as trust_basis "override"/"tls" in the verdict):
 *     --trusted-key B64 (repeatable)   --governance-key B64   --allow-tls-directory
 */
import { readFileSync, statSync } from 'node:fs';
import { verify, boundedFetch, fetchLegacyDirectory, oneLine, safeJson, parseJsonStrict, EXIT } from '../src/index.mjs';

const DEFAULT_DIRECTORY = 'https://fractalai.net.co/.well-known/x402-receipt-keys';
const DEFAULT_BASE = 'https://fractalai.net.co';
const MAX_FILE = 2 * 1024 * 1024;

const args = process.argv.slice(2);
const multi = (n) => args.flatMap((a, i) => (a === n && i + 1 < args.length ? [args[i + 1]] : []));
const one = (n) => { const m = multi(n); return m.length ? m[m.length - 1] : undefined; };
const flag = (n) => args.includes(n);
const VALUED = new Set(['--token-registry', '--kind', '--directory', '--history', '--anchor-ref', '--rpc', '--require', '--min-confirmations', '--quorum', '--now', '--trusted-key', '--governance-key']);
const positional = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && VALUED.has(args[i - 1])));

function usage(msg) {
  if (msg) process.stderr.write(`error: ${oneLine(msg)}\n`);
  process.stderr.write('usage: fractalai-verify <receipt.json|64-hex id|https URL> [--kind K] [--directory URL|FILE] [--anchors] [--rpc CHAIN=URL] [--require L1,L2] [--json]\n');
  process.exit(EXIT.USAGE);
}
function readText(p) {
  const st = statSync(p);
  if (!st.isFile()) throw new Error(`${p} is not a regular file`);
  if (st.size > MAX_FILE) throw new Error(`${p} is larger than ${MAX_FILE} bytes`);
  return readFileSync(p, 'utf8');
}
const isUrl = (s) => /^https:\/\//i.test(s);
const isId = (s) => /^[0-9a-f]{64}$/.test(s);
const load = async (s) => (isUrl(s) ? boundedFetch(s, { headers: { accept: 'application/json' } }) : readText(s));

async function main() {
  if (positional.length !== 1) usage('exactly one receipt argument is required');
  const target = positional[0];
  let receiptText, expectedId;
  try {
    if (isId(target)) { expectedId = target; receiptText = await boundedFetch(`${DEFAULT_BASE}/api/midas/alerts/receipt/${target}`, { headers: { accept: 'application/json' } }); }
    else receiptText = await load(target);
  } catch (e) { process.stderr.write(`error: cannot read receipt: ${oneLine(e.detail ?? e.message)}\n`); process.exit(EXIT.INPUT); }

  // Anchor records (deployments/anchors/*.json) wrap the receipt: { seal, anchor }. Unwrap with the strict parser.
  let recordAnchor;
  try {
    const top = parseJsonStrict(receiptText);
    if (top && typeof top === 'object' && !Array.isArray(top) && top.seal && !top.canonical && !top.body) {
      receiptText = JSON.stringify(top.seal);
      if (top.anchor) recordAnchor = JSON.stringify(top.anchor.chain === 'solana' ? { chain: 'solana', cluster: top.anchor.cluster, signature: top.anchor.signature } : top.anchor);
    }
  } catch { /* the kernel reports the parse error with its code */ }
  const opts = { kinds: multi('--kind').length ? multi('--kind') : ['midas-alert'], expectedId, policy: {} };
  const trusted = multi('--trusted-key');
  if (trusted.length) opts.trustedKeys = trusted;
  else {
    try { const src = one('--directory') ?? DEFAULT_DIRECTORY; opts.directory = isUrl(src) ? (await fetchLegacyDirectory(src)).text : await load(src); } catch (e) { process.stderr.write(`error: cannot read key directory: ${oneLine(e.detail ?? e.message)}\n`); process.exit(EXIT.INPUT); }
    const hist = multi('--history');
    if (hist.length) opts.directoryHistory = '[' + hist.map(readText).join(',') + ']';
  }
  if (one('--governance-key')) opts.governanceKey = one('--governance-key');
  if (flag('--allow-tls-directory')) opts.allowTlsDirectory = true;
  if (flag('--anchors')) opts.checkAnchors = true;
  if (flag('--onchain')) opts.checkOnchain = true;
  if (flag('--allow-unfinalized-payment')) opts.policy.allowUnfinalizedPayment = true;
  if (one('--token-registry')) opts.tokenRegistry = readText(one('--token-registry'));
  if (one('--anchor-ref')) opts.anchors = readText(one('--anchor-ref'));
  else if (recordAnchor) opts.anchors = recordAnchor;
  const rpc = {};
  for (const r of multi('--rpc')) { const i = r.indexOf('='); if (i <= 0) usage(`bad --rpc ${r}`); (rpc[r.slice(0, i)] ||= []).push(r.slice(i + 1)); }
  if (Object.keys(rpc).length) opts.rpc = rpc;
  if (one('--require')) opts.policy.require = one('--require').split(',').map((s) => s.trim()).filter(Boolean);
  if (flag('--allow-testnet')) opts.policy.allowTestnetAnchors = true;
  if (flag('--known-anchorer')) opts.policy.requireKnownAnchorer = true;
  if (one('--min-confirmations')) opts.policy.minConfirmations = Number(one('--min-confirmations'));
  if (one('--quorum')) opts.policy.rpcQuorum = Number(one('--quorum'));
  if (one('--now')) opts.now = Number(one('--now'));

  const v = await verify(receiptText, opts);
  if (flag('--json')) process.stdout.write(safeJson(v) + '\n');
  else {
    const L = v.levels;
    const fmt = (x) => (x === true ? 'yes' : x === false ? 'NO' : '-');
    process.stdout.write(`${v.valid ? 'VALID' : 'INVALID'}  kind=${oneLine(v.kind ?? '?')}  trust_basis=${v.trust_basis}\n`);
    process.stdout.write(`  integrity=${fmt(L.integrity)} authentic=${fmt(L.authentic)} trusted=${fmt(L.trusted)} time_anchored=${fmt(L.time_anchored)} finalized=${fmt(L.finalized)} onchain=${fmt(L.onchain)}\n`);
    if (v.key) process.stdout.write(`  key kid=${oneLine(v.key.kid)} status=${oneLine(v.key.status ?? '-')} evaluated_at=${oneLine(v.key.evaluated_at ?? '-')} (${oneLine(v.key.time_basis ?? '-')})\n`);
    if (v.directory) process.stdout.write(`  directory epoch=${v.directory.epoch} root=${oneLine(v.directory.root)}\n`);
    if (v.onchain) process.stdout.write(`  onchain chain=${v.onchain.chain_id} ${oneLine(v.onchain.symbol)} ${oneLine(v.onchain.amount)} ${oneLine(v.onchain.from)} -> ${oneLine(v.onchain.to)} block=${v.onchain.block_number} conf=${v.onchain.confirmations} finalized=${v.onchain.finalized} rpc=${v.onchain.rpc_count}\n`);
    for (const a of v.anchors) process.stdout.write(`  anchor ${oneLine(a.ref)}: ${a.counts ? 'OK' : 'refused'}${a.facts ? ` time=${a.facts.time} finalized=${a.facts.finalized} class=${a.facts.network_class}` : ''}\n`);
    if (v.overrides.length) process.stdout.write(`  overrides: ${oneLine(v.overrides.join(', '))}\n`);
    for (const r of v.reasons) process.stdout.write(`  [${r.level}] ${r.code}: ${oneLine(r.detail, 300)}\n`);
  }
  process.exit(v.exit_code);
}
main().catch((e) => { process.stderr.write(`internal error: ${oneLine(e?.message ?? e)}\n`); process.exit(EXIT.INPUT); });
