#!/usr/bin/env node
/**
 * fractalai-stablecoin-receipt — issue a latam-stablecoin-receipt (spec/TRUST-KERNEL.md §12).
 *
 *   fractalai-stablecoin-receipt keygen --out FILE
 *       write a fresh EPHEMERAL ML-DSA-65 seed key (mode 0600). For tests: it is listed in no directory.
 *   fractalai-stablecoin-receipt issue --chain ID --tx 0x… --key FILE [options]
 *       --log-index N            the Transfer log to certify (default: the single pinned-token Transfer of the tx)
 *       --rpc URL                JSON-RPC endpoint (repeatable: every one must agree; default: the registry's)
 *       --reference REF          unverified label for reconciliation ([A-Za-z0-9._:/-]{0,64}), e.g. an invoice id
 *       --min-confirmations N    (default 1)   --allow-unfinalized   (default: refuse until the block is finalized)
 *       --out FILE               write the receipt there (default: stdout)
 *   fractalai-stablecoin-receipt tokens
 *       print the pinned registry (chain, address, symbol, decimals)
 *
 * The key file is read once and never printed. Exit codes: 0 issued · 2 usage · 3 input · 4 refused (reason code on stderr).
 * Read-only JSON-RPC: no transaction is ever sent.
 */
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { issueStablecoinReceipt, loadKey, generateKeyFile, BAKED_STABLECOIN_REGISTRY } from '../src/issue.mjs';
import { oneLine } from '../../kernel/src/index.mjs';

const args = process.argv.slice(2);
const cmd = args[0];
const multi = (n) => args.flatMap((a, i) => (a === n && i + 1 < args.length ? [args[i + 1]] : []));
const one = (n) => { const m = multi(n); return m.length ? m[m.length - 1] : undefined; };
const flag = (n) => args.includes(n);
const usage = (m) => { if (m) process.stderr.write(`error: ${oneLine(m)}\n`); process.stderr.write('usage: fractalai-stablecoin-receipt keygen --out FILE | issue --chain ID --tx 0x… --key FILE [--log-index N] [--rpc URL]… [--reference REF] [--out FILE] | tokens\n'); process.exit(2); };

async function main() {
  if (cmd === 'tokens') {
    for (const t of BAKED_STABLECOIN_REGISTRY.tokens) process.stdout.write(`${t.chain_id}\t${t.address}\t${t.symbol}\t${t.decimals}\t${t.currency}\t${t.issuer}\n`);
    return 0;
  }
  if (cmd === 'keygen') {
    const out = one('--out');
    if (!out) usage('--out FILE is required');
    writeFileSync(out, generateKeyFile(), { mode: 0o600, flag: 'wx' });
    const k = loadKey(readFileSync(out, 'utf8'));
    process.stdout.write(`wrote ${out} (ephemeral test key) kid=${k.kid}\npublic_key_b64=${k.publicKeyB64}\n`);
    return 0;
  }
  if (cmd !== 'issue') usage();
  const chainId = Number(one('--chain'));
  const txHash = one('--tx');
  const keyPath = one('--key');
  if (!Number.isSafeInteger(chainId) || !txHash || !keyPath) usage('--chain, --tx and --key are required');
  let key;
  try {
    const st = statSync(keyPath);
    if (!st.isFile() || st.size > 64 * 1024) throw new Error('key file is not a small regular file');
    key = loadKey(readFileSync(keyPath, 'utf8'));
  } catch (e) { process.stderr.write(`error: cannot load key: ${oneLine(e.detail ?? e.message)}\n`); return 3; }
  const li = one('--log-index');
  try {
    const { text, facts } = await issueStablecoinReceipt({
      chainId, txHash, logIndex: li === undefined ? undefined : Number(li), key, rpcUrls: multi('--rpc'), reference: one('--reference') ?? '',
      minConfirmations: one('--min-confirmations') ? Number(one('--min-confirmations')) : 1, requireFinalized: !flag('--allow-unfinalized'),
    });
    if (one('--out')) writeFileSync(one('--out'), text, { flag: 'wx' }); else process.stdout.write(text);
    process.stderr.write(`issued: ${facts.symbol} ${facts.amount} ${facts.from} -> ${facts.to} block ${facts.block_number} (${facts.finalized ? 'finalized' : 'confirmed'}, ${facts.confirmations} conf, ${facts.rpc_count} rpc) kid=${key.kid}\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`refused: ${oneLine(e.code ?? 'ERROR')}: ${oneLine(e.detail ?? e.message, 400)}\n`);
    return 4;
  }
}
main().then((c) => process.exit(c ?? 0), (e) => { process.stderr.write(`internal error: ${oneLine(e?.message ?? e)}\n`); process.exit(3); });
