#!/usr/bin/env node
/**
 * anchor-solana-memo — anchor ONE public ML-DSA-65-signed FractalAI receipt on Solana with the SPL Memo
 * program (scheme fractalai.pqc-receipt-anchor/1), wait for `finalized`, verify it back from the RPC and
 * write deployments/anchors/solana-<cluster>-<rid8>.json.
 *
 *   cd verifier && npm install && cd ..
 *   node scripts/anchor-solana-memo.mjs                              # devnet (default), airdrops if empty
 *   node scripts/anchor-solana-memo.mjs --cluster mainnet-beta       # mainnet: needs a funded keypair
 *
 * Options: --cluster devnet|mainnet-beta  --keypair <path> (default ~/.config/fractalai/solana-anchor.json)
 *          --rpc <url>  --receipt <receipt_id>  --dry-run (build + print the memo, send nothing)  --force
 *
 * The memo is RECOMPUTED from the public receipt (never copied by hand) and the receipt's ML-DSA-65
 * signature + key-directory status are checked locally BEFORE anything is sent. The keypair file never
 * leaves the machine and only its public key is printed. No SDK: see verifier/src/solana-anchor.mjs.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ANCHOR_SCHEME, MEMO_PROGRAM_ID, DEFAULT_RPC, explorerTx, keypairFromSolanaJson, sealFromReceipt,
  deriveAnchorIds, buildMemo, verifyReceiptSignature, buildMemoMessage, signTransaction, rpc, verifySolanaAnchor,
} from '../verifier/src/solana-anchor.mjs';
import { trustedKeysFromDirectory } from '../verifier/src/verify-anchor.mjs';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const flag = (n) => args.includes(n);

const cluster = opt('--cluster', 'devnet');
if (!['devnet', 'mainnet-beta'].includes(cluster)) { console.error(`unknown --cluster '${cluster}' (devnet | mainnet-beta)`); process.exit(2); }
const rpcUrl = opt('--rpc', DEFAULT_RPC[cluster]);
const keypairPath = opt('--keypair', path.join(homedir(), '.config', 'fractalai', 'solana-anchor.json'));
const BASE = process.env.FRACTALAI_BASE || 'https://fractalai.net.co';
const RECEIPT_ID = opt('--receipt', 'fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee');
const LAMPORTS = 1_000_000_000;
const MIN_MAINNET_LAMPORTS = 100_000; // 0.0001 SOL
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const die = (m) => { console.error(`ABORT: ${m}`); process.exit(1); };

// 1) Keypair (public key only is ever printed).
if (!existsSync(keypairPath)) die(`keypair not found at ${keypairPath}`);
const kp = keypairFromSolanaJson(JSON.parse(readFileSync(keypairPath, 'utf8')));
console.log(`cluster   ${cluster}  rpc ${rpcUrl}`);
console.log(`signer    ${kp.pubkey}`);

// 2) Public receipt → verified seal → canonical memo.
const getJson = async (u) => { const r = await fetch(u, { signal: AbortSignal.timeout(20000) }); if (!r.ok) throw new Error(`${u} HTTP ${r.status}`); return r.json(); };
const receipt = await getJson(`${BASE}/api/midas/alerts/receipt/${RECEIPT_ID}`);
const seal = sealFromReceipt(receipt);
if (seal.content_id !== RECEIPT_ID) die('receipt endpoint returned a different receipt id');
const dir = await getJson(`${BASE}/.well-known/x402-receipt-keys`);
const trusted = trustedKeysFromDirectory(dir);
const sv = verifyReceiptSignature(seal, trusted);
if (!sv.ok) die(`receipt does not verify (${sv.reason}) — refusing to anchor`);
const ids = deriveAnchorIds(seal);
const memo = buildMemo(ids);
const entry = (dir.keys || []).find((k) => k.public_key_b64 === seal.public_key);
console.log(`receipt   ${RECEIPT_ID}  ML-DSA-65 OK, key ${entry?.kid} (${entry?.status}) in directory epoch ${dir.epoch}`);
console.log(`memo      ${memo}  (${Buffer.byteLength(memo)} bytes)`);

const rid8 = RECEIPT_ID.slice(0, 8);
const outFile = path.join(ROOT, 'deployments', 'anchors', `solana-${cluster}-${rid8}.json`);
if (flag('--dry-run')) { console.log('dry-run: nothing sent'); process.exit(0); }
if (existsSync(outFile) && !flag('--force')) die(`${path.relative(ROOT, outFile)} already exists — this receipt is already anchored on ${cluster} (pass --force to anchor again)`);

// 3) Balance. Mainnet: never airdrop, abort if underfunded. Devnet: airdrop if needed.
const balance = async () => (await rpc(rpcUrl, 'getBalance', [kp.pubkey, { commitment: 'confirmed' }])).value;
let bal = await balance();
const rentMin = await rpc(rpcUrl, 'getMinimumBalanceForRentExemption', [0]);
console.log(`balance   ${bal / LAMPORTS} SOL (rent-exempt minimum for a wallet ${rentMin / LAMPORTS} SOL)`);
if (cluster === 'mainnet-beta') {
  if (bal < MIN_MAINNET_LAMPORTS) die(`balance ${bal / LAMPORTS} SOL < 0.0001 SOL. Fund ${kp.pubkey} with ≥0.001 SOL (wallets below the rent-exempt minimum of ${rentMin / LAMPORTS} SOL cannot exist) and re-run.`);
  if (bal < rentMin + 5000) die(`balance ${bal / LAMPORTS} SOL would fall below the rent-exempt minimum after the fee; fund ≥0.001 SOL.`);
} else if (bal < rentMin + 10_000) {
  console.log('devnet: requesting airdrop of 1 SOL …');
  const airdropRpcs = [rpcUrl, ...new Set(['https://api.devnet.solana.com', 'https://rpc.ankr.com/solana_devnet', 'https://devnet.helius-rpc.com'])].filter((u, i, a) => a.indexOf(u) === i);
  let ok = false;
  for (const u of airdropRpcs) {
    try {
      const s = await rpc(u, 'requestAirdrop', [kp.pubkey, LAMPORTS]);
      console.log(`  airdrop tx ${s} via ${u}`);
      for (let i = 0; i < 40 && !ok; i++) { await sleep(1500); if ((await balance()) >= rentMin + 10_000) ok = true; }
      if (ok) break;
    } catch (e) { console.log(`  airdrop via ${u} failed: ${e.message}`); }
  }
  if (!ok) die(`devnet faucet unavailable. Fund ${kp.pubkey} at https://faucet.solana.com (devnet) and re-run.`);
  bal = await balance();
  console.log(`balance   ${bal / LAMPORTS} SOL`);
}

// 4) Build, sign, simulate, send.
const { value: { blockhash, lastValidBlockHeight } } = await rpc(rpcUrl, 'getLatestBlockhash', [{ commitment: 'finalized' }]);
const message = buildMemoMessage({ payer32: kp.publicKey, recentBlockhash: blockhash, memo });
const fee = (await rpc(rpcUrl, 'getFeeForMessage', [message.toString('base64'), { commitment: 'finalized' }])).value;
console.log(`fee       ${fee} lamports (${fee / LAMPORTS} SOL)`);
if (fee === null || fee > 10_000) die(`unexpected fee ${fee}`);
const { signature, wire } = signTransaction(message, kp.privateKey);
const sim = await rpc(rpcUrl, 'simulateTransaction', [wire.toString('base64'), { encoding: 'base64', sigVerify: true, commitment: 'finalized' }]);
if (sim.value.err) die(`simulation failed: ${JSON.stringify(sim.value.err)} ${JSON.stringify(sim.value.logs)}`);
console.log(`simulate  ok (${(sim.value.logs || []).length} log lines)`);
const sent = await rpc(rpcUrl, 'sendTransaction', [wire.toString('base64'), { encoding: 'base64', preflightCommitment: 'finalized', maxRetries: 10 }]);
if (sent !== signature) die(`RPC returned signature ${sent} != locally computed ${signature}`);
console.log(`sent      ${signature}`);

// 5) Wait for finalized (re-broadcast until the blockhash expires).
let status = null;
for (let i = 0; i < 120; i++) {
  await sleep(2000);
  status = (await rpc(rpcUrl, 'getSignatureStatuses', [[signature], { searchTransactionHistory: true }])).value[0];
  if (status?.err) die(`tx failed on-chain: ${JSON.stringify(status.err)}`);
  if (status?.confirmationStatus === 'finalized') break;
  if (!status) {
    const h = await rpc(rpcUrl, 'getBlockHeight', [{ commitment: 'confirmed' }]);
    if (h > lastValidBlockHeight) die('blockhash expired before the tx landed; nothing was anchored — re-run');
    if (i % 5 === 4) await rpc(rpcUrl, 'sendTransaction', [wire.toString('base64'), { encoding: 'base64', skipPreflight: true }]).catch(() => {});
  }
}
if (status?.confirmationStatus !== 'finalized') die(`not finalized after 4 min (last status ${JSON.stringify(status)}); check ${explorerTx(signature, cluster)}`);
console.log(`finalized slot ${status.slot}`);

// 6) Verify back from the RPC exactly as a third party would, then write the record.
let v;
for (let i = 0; i < 10; i++) { v = await verifySolanaAnchor({ signature, receipt, expectedSigner: kp.pubkey, cluster, rpcUrl, trustedPublicKeysB64: trusted }); if (v.valid || v.tx_found) break; await sleep(3000); }
if (!v.valid) die(`anchored but self-verification failed: ${v.reason}`);
const record = {
  source_receipt_url: `${BASE}/api/midas/alerts/receipt/${RECEIPT_ID}`,
  key_directory: `${BASE}/.well-known/x402-receipt-keys`,
  seal: { algorithm: seal.algorithm, domain: seal.domain, content_id: seal.content_id, public_key: seal.public_key, signature: seal.signature, canonical: seal.canonical, emitted_at: seal.emitted_at },
  anchor: {
    scheme: ANCHOR_SCHEME,
    chain: 'solana',
    cluster,
    program: MEMO_PROGRAM_ID,
    signature,
    slot: v.slot,
    block_time: v.block_time,
    status: 'finalized',
    signer: kp.pubkey,
    memo,
    memo_sha256: (await import('node:crypto')).createHash('sha256').update(memo, 'utf8').digest('hex'),
    receipt_id: '0x' + ids.receipt_id,
    payload_hash: '0x' + ids.payload_hash,
    kid: ids.kid,
    observed_at: ids.observed_at,
    fee_lamports: fee,
    explorer_tx: explorerTx(signature, cluster),
    verify: `node verifier/verify-solana-anchor.mjs --record deployments/anchors/solana-${cluster}-${rid8}.json`,
  },
};
writeFileSync(outFile, JSON.stringify(record, null, 2) + '\n');
console.log(`VALID — ${v.reason}`);
console.log(`record    ${path.relative(ROOT, outFile)}`);
console.log(`explorer  ${explorerTx(signature, cluster)}`);
