// SPDX-License-Identifier: Apache-2.0
// End-to-end test of pay.mjs on LOCAL anvil forks of Base and Polygon mainnet. No real money moves:
// the payer, relayer and payTo are anvil's public test accounts, token balances are written into fork storage.
//   node test/run.mjs                      (needs `anvil` on PATH or ANVIL=/path/to/anvil)
//   BASE_FORK_URL=… POLYGON_FORK_URL=…    (optional upstream RPCs to fork from)
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ethers } from 'ethers';
import { startServer } from './server.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const ANVIL = process.env.ANVIL || 'anvil';
// EPHEMERAL keys generated for this run only (held in memory, never written anywhere). anvil's well-known
// default accounts are NOT used: on Base and Polygon mainnet they carry EIP-7702 delegations, so tokens and
// Permit2 check their signatures through ERC-1271 and an EOA signature is rejected.
const PAYER_KEY = ethers.Wallet.createRandom().privateKey;
const RELAYER_KEY = ethers.Wallet.createRandom().privateKey;
const PAY_TO = ethers.Wallet.createRandom().address;
const PAYER = new ethers.Wallet(PAYER_KEY).address;

const FORKS = {
  base: { chainId: 8453, network: 'eip155:8453', port: 18545, url: process.env.BASE_FORK_URL || 'https://mainnet.base.org' },
  polygon: { chainId: 137, network: 'eip155:137', port: 18546, url: process.env.POLYGON_FORK_URL || 'https://polygon-bor-rpc.publicnode.com' },
};
// Same tokens, EIP-712 domains, methods and amounts as the production witness 402 of 2026-10-11 (USD 0.005).
const OFFERS = [
  { id: 'USDC', symbol: 'USDC', currency: 'USD', rate: '1', fork: 'base', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', decimals: 6, amount: '5000', method: 'eip3009', name: 'USD Coin', version: '2' },
  { id: 'MXNB', symbol: 'MXNB', currency: 'MXN', rate: '18.4163', fork: 'base', asset: '0xF197FFC28c23E0309B5559e7a166f2c6164C80aA', decimals: 6, amount: '92100', method: 'eip3009', name: 'MXNB', version: '2' },
  { id: 'WCOP_BASE', symbol: 'wCOP', currency: 'COP', rate: '3194.44', fork: 'base', asset: '0x8a1D45e102e886510e891d2Ec656a708991e2D76', decimals: 18, amount: '15980000000000000000', method: 'permit2', name: 'Peso Colombiano', version: '1' },
  { id: 'COPM', symbol: 'COPM', currency: 'COP', rate: '3194.44', fork: 'polygon', asset: '0x12050c705152931cFEe3DD56c52Fb09Dea816C23', decimals: 18, amount: '15980000000000000000', method: 'permit2', name: 'COP Minteo', version: '1' },
  { id: 'BRLA', symbol: 'BRLA', currency: 'BRL', rate: '4.9892', fork: 'polygon', asset: '0xE6A537a407488807F0bbeb0038B79004f19DDDFb', decimals: 18, amount: '25000000000000000', method: 'permit2', name: 'BRLA Token', version: '1' },
].map((o) => ({ ...o, network: FORKS[o.fork].network, chainId: FORKS[o.fork].chainId, rpc: `http://127.0.0.1:${FORKS[o.fork].port}` }));

const ERC20 = ['function balanceOf(address) view returns (uint256)', 'function allowance(address,address) view returns (uint256)'];
const procs = [];
let failures = 0;
const check = (name, cond, detail = '') => { console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!cond) failures++; };

async function startFork(f) {
  const p = spawn(ANVIL, ['--fork-url', f.url, '--port', String(f.port), '--silent', '--no-storage-caching'], { stdio: 'ignore' });
  procs.push(p);
  const provider = new ethers.JsonRpcProvider(`http://127.0.0.1:${f.port}`, f.chainId, { staticNetwork: true });
  for (let i = 0; i < 120; i++) {
    try { await provider.getBlockNumber(); return provider; } catch { await new Promise((r) => setTimeout(r, 500)); }
  }
  throw new Error(`anvil fork of ${f.url} did not start`);
}

/** Write `amount` into the token's balance mapping for `who` (plain or ERC-7201 OZ v5 layout), verified by balanceOf. */
async function setTokenBalance(provider, token, who, amount) {
  const t = new ethers.Contract(token, ERC20, provider);
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const OZ5 = '0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00';
  const candidates = [OZ5, ...Array.from({ length: 120 }, (_, i) => ethers.toBeHex(i, 32))];
  for (const base of candidates) {
    for (const slot of [ethers.keccak256(coder.encode(['address', 'bytes32'], [who, base]))]) {
      const before = await provider.send('eth_getStorageAt', [token, slot, 'latest']);
      await provider.send('anvil_setStorageAt', [token, slot, ethers.toBeHex(amount, 32)]);
      if ((await t.balanceOf(who)) === amount) return base;
      await provider.send('anvil_setStorageAt', [token, slot, before]);
    }
  }
  throw new Error(`balance slot of ${token} not found`);
}

function pay(args, env = {}) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [join(here, '..', 'pay.mjs'), ...args, '--json'], { env: { ...process.env, PAYER_PRIVATE_KEY: PAYER_KEY, ...env } });
    let out = '', err = '';
    c.stdout.on('data', (d) => (out += d)); c.stderr.on('data', (d) => (err += d));
    c.on('close', (code) => {
      let result = null; try { result = JSON.parse(out.trim().split('\n').pop()); } catch { /* none */ }
      const leak = (out + err).toLowerCase().includes(PAYER_KEY.slice(2).toLowerCase());
      resolve({ code, result, out, err, leak });
    });
  });
}

const providers = {};
try {
  console.log('starting anvil forks (Base, Polygon)…');
  [providers.base, providers.polygon] = await Promise.all([startFork(FORKS.base), startFork(FORKS.polygon)]);
  console.log(`  Base fork block ${await providers.base.getBlockNumber()}, Polygon fork block ${await providers.polygon.getBlockNumber()}`);
  for (const p of Object.values(providers)) for (const w of [PAYER, new ethers.Wallet(RELAYER_KEY).address]) await p.send('anvil_setBalance', [w, ethers.toQuantity(ethers.parseEther('100'))]);
  for (const o of OFFERS) {
    const slot = await setTokenBalance(providers[o.fork], o.asset, PAYER, BigInt(o.amount) * 10n);
    console.log(`  funded test payer with 10 x price of ${o.symbol} (${o.network}) via balance mapping at slot ${slot.startsWith('0x52c6') ? 'ERC-7201 0x52c6…' : BigInt(slot)}`);
  }

  const srv = await startServer({ offers: OFFERS, payTo: PAY_TO, relayerKey: RELAYER_KEY });
  const common = (o) => ['--url', srv.url, '--token', o.symbol, '--network', o.network, '--rpc', o.rpc, '--yes'];
  const bal = (o, who) => new ethers.Contract(o.asset, ERC20, providers[o.fork]).balanceOf(who);
  const run = async (o, { extra = [], faults = [], label = o.symbol } = {}) => {
    srv.faults.push(...faults);
    const logStart = srv.log.length;
    const [b0, p0] = [await bal(o, PAY_TO), await bal(o, PAYER)];
    const r = await pay([...common(o), ...extra]);
    const [b1, p1] = [await bal(o, PAY_TO), await bal(o, PAYER)];
    const reqs = srv.log.slice(logStart);
    return { r, delta: b1 - b0, payerDelta: p0 - p1, reqs, label };
  };

  // 1) every token, happy path (Permit2 tokens start WITHOUT allowance: the client must approve once).
  for (const o of OFFERS) {
    const allowance0 = o.method === 'permit2' ? await new ethers.Contract(o.asset, ERC20, providers[o.fork]).allowance(PAYER, '0x000000000022D473030F116dDEE9F6B43aC78BA3') : null;
    const { r, delta, payerDelta, reqs } = await run(o);
    check(`${o.symbol} ${o.network} ${o.method}: paid, exit 0`, r.code === 0 && r.result?.ok === true, r.result?.error ?? '');
    check(`${o.symbol}: payTo received exactly the quoted ${ethers.formatUnits(o.amount, o.decimals)} ${o.symbol}, payer paid the same`, delta === BigInt(o.amount) && payerDelta === BigInt(o.amount), `delta=${delta}`);
    check(`${o.symbol}: one signed payment, one request, receiptId printed`, reqs.length === 1 && /^[0-9a-f]{64}$/.test(r.result?.deliveryReceipt?.receiptId ?? ''), `tx ${r.result?.transaction}`);
    if (o.method === 'permit2') check(`${o.symbol}: Permit2 approval sent once (allowance 0 -> max)`, allowance0 === 0n && (await new ethers.Contract(o.asset, ERC20, providers[o.fork]).allowance(PAYER, '0x000000000022D473030F116dDEE9F6B43aC78BA3')) === ethers.MaxUint256);
    check(`${o.symbol}: private key absent from all output`, !r.leak);
  }

  // 2) second COPM payment: allowance already there -> no approve; first attempt fails BEFORE settlement (503),
  //    the client re-sends the SAME payment and it settles exactly once.
  {
    const o = OFFERS.find((x) => x.symbol === 'COPM');
    const { r, delta, reqs } = await run(o, { faults: ['drop-before'] });
    check('COPM retry after 503: success, exit 0', r.code === 0 && r.result?.ok, r.result?.error ?? '');
    check('COPM retry: 2 requests carried the identical signed header (never re-signed)', reqs.length === 2 && reqs[0].headerSha256 === reqs[1].headerSha256);
    check('COPM retry: charged exactly once', delta === BigInt(o.amount), `delta=${delta}`);
  }
  // 3) BRLA: the server settles but answers after the client timeout -> the client must NOT pay again; it
  //    sees the Permit2 nonce consumed on-chain and reports "paid, response lost".
  {
    const o = OFFERS.find((x) => x.symbol === 'BRLA');
    const { r, delta, reqs } = await run(o, { faults: ['hang-after:8000'], extra: ['--timeout', '4000'] });
    check('BRLA lost response: exit 1, stage lost-response, paid=true', r.code === 1 && r.result?.stage === 'lost-response' && r.result?.paid === true, r.result?.error ?? '');
    check('BRLA lost response: one request only, charged exactly once', reqs.length === 1 && delta === BigInt(o.amount), `requests=${reqs.length} delta=${delta}`);
  }
  // 4) MXNB on the same path (EIP-3009): lost response detected through authorizationState.
  {
    const o = OFFERS.find((x) => x.symbol === 'MXNB');
    const { r, delta } = await run(o, { faults: ['hang-after:8000'], extra: ['--timeout', '4000'] });
    check('MXNB lost response: exit 1, paid=true, charged exactly once', r.code === 1 && r.result?.paid === true && delta === BigInt(o.amount), `delta=${delta}`);
  }
  // 5) --max guard: refuses before signing.
  {
    const o = OFFERS.find((x) => x.symbol === 'COPM');
    const { r, delta, reqs } = await run(o, { extra: ['--max', '10'] });
    check('COPM --max 10 (price 15.98): refused before signing, nothing sent', r.code === 1 && r.result?.stage === 'quote' && reqs.length === 0 && delta === 0n);
  }
  // 6) a payer address with code (anvil's default account #1 carries an EIP-7702 delegation on Polygon mainnet):
  //    refused before signing, because Permit2 would check the signature through ERC-1271.
  {
    const o = OFFERS.find((x) => x.symbol === 'BRLA');
    const anvil1 = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
    const logStart = srv.log.length;
    const r = await pay(common(o), { PAYER_PRIVATE_KEY: anvil1 });
    check('payer with EIP-7702 code: refused before signing (stage payer, exit 2), nothing sent', r.code === 2 && r.result?.stage === 'payer' && srv.log.length === logStart, r.result?.error?.slice(0, 80) ?? '');
  }
  srv.close();
} catch (e) {
  console.error('ERROR', e.message); failures++;
} finally {
  for (const p of procs) p.kill();
}
console.log(failures ? `\n${failures} FAILED` : '\nALL PASS');
process.exit(failures ? 1 : 0);
