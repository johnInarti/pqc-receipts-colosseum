#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Pay a FractalAI x402 endpoint in your local stablecoin.
//
//   PAYER_PRIVATE_KEY=0x… node pay.mjs --token MXNB --route witness [--body file.json] [--network base] --yes
//
// Without --yes nothing is signed or sent: it prints the live quote (amount in local currency + the official
// reference rate the server used) and what it would sign. The key is read ONLY from PAYER_PRIVATE_KEY and is
// never written to disk or printed. Each run signs at most ONE payment; on a timeout or 5xx it re-sends the
// SAME signed payment (the server and the chain reject a second use of its nonce, so a retry can never charge twice).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';
import { ethers } from 'ethers';
import {
  CHAINS, PERMIT2, parseChallenge, listOffers, selectOffer, formatAmount, signPayment, nonceConsumed,
  readBalances, approvePermit2, decodePaymentResponse,
} from './lib.mjs';

const HELP = `usage: node pay.mjs --token <MXNB|BRLA|COPM|COPW|wCOP|wARS|wBRL|wMXN|USDC> [options]
  --route <name>       FractalAI x402 route (default: witness) -> https://fractalai.net.co/api/x402/<name>
  --url <url>          full endpoint URL instead of --route (e.g. a local test server)
  --network <n>        chain when the token is offered on several (base, arbitrumone, polygon, worldchain or eip155:<id>)
  --body <file>        JSON request body (default: a minimal witness seal_body)
  --rpc <url>          RPC for the payment chain (balance/allowance/approve/nonce checks)
  --max <amount>       refuse to pay more than this many token units (human units, e.g. 20 for 20 COPM)
  --yes                actually sign and pay (otherwise: quote only)
  --no-approve         never send the one-time Permit2 approval; stop instead
  --timeout <ms>       per-request timeout (default 60000)    --retries <n>  re-sends of the same payment (default 3)
  --json               print one JSON result line at the end (for agents)
  --allow-contract-wallet  sign even if the payer address has code (EIP-7702 / smart account; usually fails)
  --list               list every payable offer of the route and exit
env: PAYER_PRIVATE_KEY (required with --yes)`;

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const opt = (n, d) => { const i = argv.indexOf(n); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : d; };
if (flag('--help') || flag('-h')) { console.log(HELP); process.exit(0); }
if (argv.some((a) => /^--(key|private-?key|pk)$/i.test(a))) { console.error('refusing: pass the key only via PAYER_PRIVATE_KEY'); process.exit(2); }

const JSON_OUT = flag('--json');
const log = (...m) => { if (!JSON_OUT) console.log(...m); else console.error(...m); };
const done = (code, result) => {
  if (JSON_OUT) console.log(JSON.stringify(result));
  else if (!result.ok) console.error(`ERROR      ${result.stage ? `[${result.stage}] ` : ''}${result.error}${result.paid != null ? `\npaid on-chain: ${result.paid}` : ''}`);
  process.exit(code);
};
// Settled-or-not, polled: a timed-out request may still be settling on the server.
async function settledWithin(provider, offer, payer, nonce, ms) {
  for (const end = Date.now() + ms; ; await new Promise((r) => setTimeout(r, 3000))) {
    if (await nonceConsumed(provider, offer, payer, nonce)) return true;
    if (Date.now() > end) return false;
  }
}

const url = opt('--url') || `https://fractalai.net.co/api/x402/${opt('--route', 'witness')}`;
const token = opt('--token');
const TIMEOUT = Number(opt('--timeout', '60000'));
const RETRIES = Number(opt('--retries', '3'));
const here = dirname(fileURLToPath(import.meta.url));
const VERIFIER = relative(process.cwd(), join(here, '..', '..', 'verifier', 'verify-delivery-receipt-openssl.mjs')) || 'verifier/verify-delivery-receipt-openssl.mjs';
// SHA-256 of the raw governance keys of /.well-known/x402-receipt-keys epoch 1 (see the repository README).
const PIN_ED25519 = '3e7f09b0566701962c0994dba8da89b930a091506b4fbb6472a742bcd2372877';
const PIN_MLDSA65 = 'bec0e906bf74e6f20003f073b4a0d61a99309810909b549cf4db27af159b94c1';

let bodyText = JSON.stringify({ seal_body: { resource: 'https://example.com/pay-latam-demo', note: 'paid with examples/pay-latam' } });
if (opt('--body')) { bodyText = readFileSync(opt('--body'), 'utf8'); JSON.parse(bodyText); }

async function post(headers = {}) {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json', ...headers }, body: bodyText, signal: AbortSignal.timeout(TIMEOUT), redirect: 'error' });
  return { status: r.status, headers: r.headers, text: await r.text() };
}
const errOf = (text) => { try { const j = JSON.parse(text); return j.error || j.code || text.slice(0, 300); } catch { return text.slice(0, 300); } };

try {
  // 1) Read the real 402.
  const first = await post();
  if (first.status !== 402) done(2, { ok: false, stage: 'challenge', error: `expected HTTP 402, got ${first.status}: ${errOf(first.text)}` });
  const parsed = parseChallenge(first.headers, first.text);
  const offers = listOffers(parsed);
  if (flag('--list') || !token) {
    for (const o of offers) log(`${o.symbol.padEnd(5)} ${CHAINS[o.accept.network].name.padEnd(12)} ${o.method.padEnd(7)} ${o.label || formatAmount(o.accept.amount, o.decimals) + ' ' + o.symbol}${o.fx ? `   (1 USD = ${o.fx.rate} ${o.fx.pair?.split('/')[1] ?? ''}, ${o.fx.source})` : ''}`);
    if (!token && !flag('--list')) { log('\n' + HELP); done(2, { ok: false, error: '--token is required' }); }
    done(0, { ok: true, offers: offers.map((o) => ({ symbol: o.symbol, network: o.accept.network, method: o.method, amount: o.accept.amount, label: o.label })) });
  }
  const offer = selectOffer(offers, token, opt('--network'));
  const a = offer.accept;
  const chain = CHAINS[a.network];

  const provider = new ethers.JsonRpcProvider(opt('--rpc', chain.rpc), chain.chainId, { staticNetwork: true });
  const rpcChain = Number((await provider.getNetwork()).chainId);
  const realChain = Number(await provider.send('eth_chainId', []));
  if (realChain !== chain.chainId || rpcChain !== chain.chainId) throw new Error(`RPC is on chain ${realChain}, the offer is on ${chain.chainId}`);

  const decimals = offer.decimals ?? Number(await new ethers.Contract(a.asset, ['function decimals() view returns (uint8)'], provider).decimals());
  const human = formatAmount(a.amount, decimals);
  log(`Endpoint   ${url}`);
  log(`Price      ${human} ${offer.symbol} on ${chain.name} (${a.network}), method ${offer.method}, payTo ${a.payTo}`);
  if (offer.fx) log(`Rate       1 USD = ${offer.fx.rate} ${offer.fx.pair?.split('/')[1] ?? offer.currency} — ${offer.fx.source}${offer.fx.date ? `, ${offer.fx.date}` : offer.fx.vigencia ? `, ${offer.fx.vigencia.desde}..${offer.fx.vigencia.hasta}` : ''} (official fiat reference, not the token's market price)`);
  if (opt('--max') && Number(human) > Number(opt('--max'))) done(1, { ok: false, stage: 'quote', error: `price ${human} ${offer.symbol} exceeds --max ${opt('--max')}` });

  const pk = process.env.PAYER_PRIVATE_KEY;
  if (!flag('--yes')) {
    log(`\nQuote only. Re-run with --yes (and PAYER_PRIVATE_KEY in the environment) to sign ${offer.method === 'permit2' ? 'a Permit2 PermitWitnessTransferFrom' : 'an EIP-3009 TransferWithAuthorization'} for exactly ${human} ${offer.symbol}.`);
    done(0, { ok: true, quoteOnly: true, symbol: offer.symbol, network: a.network, amount: a.amount, human, fx: offer.fx ?? null });
  }
  if (!pk || !/^(0x)?[0-9a-fA-F]{64}$/.test(pk.trim())) done(2, { ok: false, stage: 'key', error: 'PAYER_PRIVATE_KEY missing or not a 32-byte hex key' });
  const wallet = new ethers.Wallet(pk.trim(), provider);
  const payer = wallet.address;
  log(`Payer      ${payer}`);
  const code = await provider.getCode(payer);
  if (code !== '0x' && !flag('--allow-contract-wallet')) {
    done(2, { ok: false, stage: 'payer', error: `${payer} has code on ${chain.name} (${code.startsWith('0xef0100') ? 'EIP-7702 delegation' : 'contract'}): the token / Permit2 will check the signature through ERC-1271 and reject this EOA signature. Use a plain EOA, or --allow-contract-wallet to try anyway.` });
  }

  // 2) Funds and (Permit2 only) the one-time approval.
  const { balance, allowance } = await readBalances(provider, { ...offer, decimals }, payer);
  if (balance < BigInt(a.amount)) done(1, { ok: false, stage: 'balance', error: `balance ${formatAmount(balance, decimals)} ${offer.symbol} < price ${human}` });
  if (offer.method === 'permit2' && allowance < BigInt(a.amount)) {
    if (flag('--no-approve')) done(1, { ok: false, stage: 'approve', error: `no Permit2 allowance: send ${offer.symbol}.approve(${PERMIT2}, amount) once` });
    log(`Approve    one-time ${offer.symbol}.approve(Permit2 ${PERMIT2}, max) — costs ${chain.native} gas once…`);
    log(`           tx ${await approvePermit2(wallet, offer)}`);
  }

  // 3) Sign ONCE. From here on only this exact payment is ever sent.
  const signed = await signPayment(wallet, offer, parsed.challenge);
  log(`Signed     1 ${signed.method} authorization, nonce ${signed.nonce.slice(0, 18)}…`);

  let res = null;
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, Math.min(2000 * 2 ** (attempt - 1), 15000)));
      if (await nonceConsumed(provider, offer, payer, signed.nonce)) {
        done(1, { ok: false, stage: 'lost-response', paid: true, payer, nonce: signed.nonce, network: a.network,
          error: `the payment WAS settled on-chain (nonce consumed) but the response was lost. Do not pay again; look up the ${offer.symbol} Transfer from ${payer} to ${a.payTo} on ${chain.name}.` });
      }
      log(`Retry      ${attempt}/${RETRIES}: re-sending the SAME signed payment (not settled on-chain yet)`);
    }
    try {
      res = await post({ 'PAYMENT-SIGNATURE': signed.header, 'X-PAYMENT': signed.header });
    } catch (e) { log(`           ${e.name === 'TimeoutError' ? 'timeout' : 'network error'}: ${e.message}`); res = null; continue; }
    if ([429, 502, 503, 504].includes(res.status)) { log(`           HTTP ${res.status}: ${errOf(res.text)}`); continue; }
    if (res.status === 412) {
      if (offer.method !== 'permit2' || flag('--no-approve')) break;
      log('           HTTP 412 PERMIT2_ALLOWANCE_REQUIRED — approving once, then re-sending the same payment');
      log(`           tx ${await approvePermit2(wallet, offer)}`);
      continue;
    }
    break;
  }
  if (!res) done(1, { ok: false, stage: 'send', paid: await nonceConsumed(provider, offer, payer, signed.nonce), error: 'no response after retries' });
  if (res.status === 409) {
    log('           HTTP 409: this payment is already being redeemed — waiting for it on-chain…');
    const paid = await settledWithin(provider, offer, payer, signed.nonce, 90_000);
    done(1, { ok: false, stage: 'send', paid, error: `409 ${errOf(res.text)}${paid ? ' — it is settled on-chain; do not pay again' : ''}` });
  }
  if (res.status !== 200) done(1, { ok: false, stage: 'send', status: res.status, paid: await nonceConsumed(provider, offer, payer, signed.nonce), error: errOf(res.text) });

  // 4) Result + delivery receipt.
  const pr = decodePaymentResponse(res.headers) || {};
  const dr = pr.extensions?.['delivery-receipt']?.info || null;
  let body = null; try { body = JSON.parse(res.text); } catch { /* non-JSON product */ }
  log(`\nPAID       ${human} ${offer.symbol} on ${chain.name}`);
  log(`tx         ${pr.transaction || pr.txHash || '(none in PAYMENT-RESPONSE)'}${pr.settle_block_number ? `  block ${pr.settle_block_number}` : ''}`);
  if (body?.seal?.content_id) log(`seal       ${body.seal.algorithm} content_id ${body.seal.content_id}`);
  if (dr) {
    log(`receiptId  ${dr.receiptId}`);
    log(`receipt    ${dr.receiptUrl}`);
    log(`verify     node ${VERIFIER} ${dr.receiptId} \\\n             --pin-ed25519 ${PIN_ED25519} \\\n             --pin-ml-dsa-65 ${PIN_MLDSA65}    # Node 24+, OpenSSL only`);
  } else log(`receipt    ${res.headers.get('x-delivery-receipt-error') ? 'delivery receipt issuance failed on the server (payment still settled)' : 'this route returned no delivery-receipt extension'}`);
  done(0, { ok: true, symbol: offer.symbol, network: a.network, amount: a.amount, human, payer, transaction: pr.transaction || pr.txHash || null, deliveryReceipt: dr, response: body });
} catch (e) {
  const k = (process.env.PAYER_PRIVATE_KEY || '').trim().replace(/^0x/i, '').toLowerCase();
  const msg = String(e?.message ?? e);
  done(2, { ok: false, error: k ? msg.split(new RegExp(k, 'ig')).join('[redacted]') : msg });
}
