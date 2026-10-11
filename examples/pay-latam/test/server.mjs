// SPDX-License-Identifier: Apache-2.0
// MINIMAL x402 test seller for the pay-latam client. TEST ONLY: it runs against local anvil forks, never mainnet.
// It serves a 402 with the same shape as https://fractalai.net.co/api/x402/witness (PAYMENT-REQUIRED header,
// accepts[] with extra.assetTransferMethod, pricing_latam / pricing_copm, delivery-receipt declaration), then
// verifies and settles the payment itself on the fork, written independently of the client:
//   eip3009: token.transferWithAuthorization(...)    permit2: x402ExactPermit2Proxy.settle(...)
// with the same rules as production: recipient = payTo, quote <= amount <= 2 x quote, validity window, EIP-712
// signature, balance, unused nonce, Permit2 allowance (412 PERMIT2_ALLOWANCE_REQUIRED), eth_call simulation, and
// after mining the exact Transfer(payer -> payTo, amount) in the receipt. A reused nonce gets 409.
// The delivery receipt it returns is an UNSIGNED test placeholder (same reference shape, test issuer).
import http from 'node:http';
import { createHash } from 'node:crypto';
import { ethers } from 'ethers';

const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const PROXY = '0x402085c248EeA27D92E8b30b2C58ed07f9E20001';
const T3009 = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] };
const TP2 = {
  PermitWitnessTransferFrom: [{ name: 'permitted', type: 'TokenPermissions' }, { name: 'spender', type: 'address' },
    { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }, { name: 'witness', type: 'Witness' }],
  TokenPermissions: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }],
  Witness: [{ name: 'to', type: 'address' }, { name: 'validAfter', type: 'uint256' }],
};
const IFACE = new ethers.Interface([
  'function balanceOf(address) view returns (uint256)', 'function allowance(address,address) view returns (uint256)',
  'function authorizationState(address,bytes32) view returns (bool)',
  'function transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)',
  'function nonceBitmap(address,uint256) view returns (uint256)',
  'function settle(((address token,uint256 amount) permitted,uint256 nonce,uint256 deadline) permit,address owner,(address to,uint256 validAfter) witness,bytes signature)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);
const jcs = (x) => x === null || typeof x !== 'object' ? JSON.stringify(x) : Array.isArray(x) ? `[${x.map(jcs).join(',')}]` : `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${jcs(x[k])}`).join(',')}}`;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const ga = ethers.getAddress;

/**
 * offers: [{ id, symbol, currency, network, chainId, asset, decimals, amount, method, name?, version?, rpc }]
 * faults: mutable array of 'drop-before' | 'hang-after:<ms>' consumed one per paid request.
 */
export function startServer({ offers, payTo, relayerKey, port = 0, faults = [] }) {
  const providers = {}; const relayers = {};
  for (const o of offers) {
    providers[o.network] ??= new ethers.JsonRpcProvider(o.rpc, o.chainId, { staticNetwork: true });
    relayers[o.network] ??= new ethers.Wallet(relayerKey, providers[o.network]);
  }
  const used = new Set();
  const log = []; // every paid request: { header sha256, outcome }
  let base = '';

  const challenge = (error) => {
    const accepts = offers.map((o) => ({
      scheme: 'exact', network: o.network, amount: o.amount, payTo, asset: o.asset, maxTimeoutSeconds: 300,
      extra: { assetTransferMethod: o.method, ...(o.name ? { name: o.name, version: o.version } : {}), ...(o.decimals != null && o.symbol !== 'COPM' ? { decimals: o.decimals } : {}) },
    }));
    const c = {
      x402Version: 2, error: error || 'Payment required',
      resource: { url: `${base}/api/x402/witness`, description: 'TEST seller (anvil fork)', mimeType: 'application/json' },
      accepts,
      extensions: { 'delivery-receipt': { info: { version: 1, issuer: base, keyDirectory: `${base}/.well-known/x402-receipt-keys`, algorithms: ['ed25519', 'ml-dsa-65'], deliveryMode: 'body', receiptTransport: 'reference' } } },
    };
    const fx = (o) => ({ pair: `USD/${o.currency}`, rate: o.rate, date: '2026-10-09', source: 'TEST fixture (copied rate, not live)', price_usd_atomic: '5000' });
    const pricing_latam = {}; let pricing_copm;
    for (const o of offers) {
      const p = { symbol: o.symbol, currency: o.currency, network: o.network, asset: o.asset, decimals: o.decimals, amount: o.amount, label: `${ethers.formatUnits(o.amount, o.decimals)} ${o.symbol}`, method: o.method, fx: fx(o) };
      if (o.symbol === 'COPM') pricing_copm = { network: o.network, asset: o.asset, amount: o.amount, label: p.label, fx: fx(o) };
      else if (o.symbol !== 'USDC') pricing_latam[o.id] = p;
    }
    return { c, body: { ...c, ...(pricing_copm ? { pricing_copm } : {}), pricing_latam } };
  };
  const send = (res, status, obj, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(obj)); };
  const send402 = (res, error) => { const { c, body } = challenge(error); send(res, 402, body, { 'PAYMENT-REQUIRED': Buffer.from(JSON.stringify(c)).toString('base64') }); };

  async function verifyAndSettle(j) {
    const acc = j.accepted || {};
    const o = offers.find((x) => x.network === (j.network ?? acc.network) && acc.asset && ga(x.asset) === ga(acc.asset));
    if (!o || (j.scheme ?? acc.scheme) !== 'exact') return { status: 402, error: 'unknown offer' };
    const p = providers[o.network]; const relayer = relayers[o.network];
    const now = BigInt(Math.floor(Date.now() / 1000));
    const call = async (to, fn, args) => IFACE.decodeFunctionResult(fn, await p.call({ to, data: IFACE.encodeFunctionData(fn, args) }))[0];
    const q = BigInt(o.amount);
    const amountOk = (v) => v >= q && v <= 2n * q;
    let to, fn, args, from, amount, nonceKey;
    if (o.method === 'eip3009') {
      const a = j.payload?.authorization; if (!a) return { status: 402, error: 'not an eip3009 payload' };
      from = ga(a.from); amount = BigInt(a.value); nonceKey = `${o.chainId}:${o.asset}:${from}:${a.nonce}`.toLowerCase();
      if (ga(a.to) !== ga(payTo)) return { status: 402, error: 'recipient mismatch' };
      if (!amountOk(amount)) return { status: 402, error: 'amount mismatch' };
      if (BigInt(a.validAfter) > now || BigInt(a.validBefore) < now + 6n) return { status: 402, error: 'outside validity window' };
      const rec = ethers.verifyTypedData({ name: o.name, version: o.version, chainId: o.chainId, verifyingContract: o.asset }, T3009,
        { from, to: ga(a.to), value: amount, validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore), nonce: a.nonce }, j.payload.signature);
      if (rec !== from) return { status: 402, error: 'invalid signature' };
      if (await call(o.asset, 'balanceOf', [from]) < amount) return { status: 402, error: 'insufficient balance' };
      if (await call(o.asset, 'authorizationState', [from, a.nonce])) return { status: 409, error: 'nonce used on-chain' };
      const s = ethers.Signature.from(j.payload.signature);
      to = o.asset; fn = 'transferWithAuthorization'; args = [from, ga(a.to), amount, BigInt(a.validAfter), BigInt(a.validBefore), a.nonce, s.v, s.r, s.s];
    } else {
      const a = j.payload?.permit2Authorization; if (!a) return { status: 402, error: 'not a permit2 payload' };
      from = ga(a.from); amount = BigInt(a.permitted.amount); nonceKey = `${o.chainId}:permit2:${from}:${a.nonce}`.toLowerCase();
      if (ga(a.spender) !== ga(PROXY)) return { status: 402, error: 'spender must be x402ExactPermit2Proxy' };
      if (ga(a.witness.to) !== ga(payTo)) return { status: 402, error: 'witness.to mismatch' };
      if (ga(a.permitted.token) !== ga(o.asset)) return { status: 402, error: 'token mismatch' };
      if (!amountOk(amount)) return { status: 402, error: 'amount mismatch' };
      if (BigInt(a.witness.validAfter) > now || BigInt(a.deadline) < now + 6n) return { status: 402, error: 'outside validity window' };
      const msg = { permitted: { token: ga(a.permitted.token), amount }, spender: ga(a.spender), nonce: BigInt(a.nonce), deadline: BigInt(a.deadline), witness: { to: ga(a.witness.to), validAfter: BigInt(a.witness.validAfter) } };
      if (ethers.verifyTypedData({ name: 'Permit2', chainId: o.chainId, verifyingContract: PERMIT2 }, TP2, msg, j.payload.signature) !== from) return { status: 402, error: 'invalid signature' };
      if (await call(o.asset, 'allowance', [from, PERMIT2]) < amount) return { status: 412, error: 'permit2_allowance_required', code: 'PERMIT2_ALLOWANCE_REQUIRED' };
      if (await call(o.asset, 'balanceOf', [from]) < amount) return { status: 402, error: 'insufficient balance' };
      const n = BigInt(a.nonce);
      if ((await call(PERMIT2, 'nonceBitmap', [from, n >> 8n]) >> (n & 255n)) & 1n) return { status: 409, error: 'nonce used on-chain' };
      to = PROXY; fn = 'settle'; args = [{ permitted: msg.permitted, nonce: msg.nonce, deadline: msg.deadline }, from, msg.witness, j.payload.signature];
    }
    if (used.has(nonceKey)) return { status: 409, error: 'This payment authorization (nonce) has already been redeemed.' };
    const data = IFACE.encodeFunctionData(fn, args);
    try { await p.call({ to, data, from: relayer.address }); } catch (e) { return { status: 402, error: `simulation failed: ${e.shortMessage || e.message}` }; }
    used.add(nonceKey); // reserve BEFORE broadcasting, as production does
    const tx = await relayer.sendTransaction({ to, data });
    const r = await tx.wait(1);
    const paid = r.status === 1 && r.logs.some((l) => {
      if (ga(l.address) !== ga(o.asset)) return false;
      try { const ev = IFACE.parseLog(l); return ev?.name === 'Transfer' && ga(ev.args[0]) === from && ga(ev.args[1]) === ga(payTo) && ev.args[2] === amount; } catch { return false; }
    });
    if (!paid) { used.delete(nonceKey); return { status: 402, error: 'settle mined without the expected Transfer' }; }
    return { status: 200, o, settlement: { success: true, scheme: 'exact', network: o.network, asset: o.asset, symbol: o.symbol, payTo, payer: from, amount: amount.toString(), transaction: tx.hash, settle_block_number: r.blockNumber, settlementMode: o.method } };
  }

  const server = http.createServer(async (req, res) => {
    try {
      let raw = ''; for await (const c of req) raw += c;
      if (req.method !== 'POST' || !req.url.startsWith('/api/x402/witness')) return send(res, 404, { error: 'not found' });
      const header = req.headers['payment-signature'] || req.headers['x-payment'];
      let body; try { body = JSON.parse(raw); } catch { body = {}; }
      if (!header) return send402(res);
      if (!body.seal_body || typeof body.seal_body !== 'object') return send(res, 400, { error: 'seal_body (object) is required' });
      const fault = faults.shift();
      const entry = { headerSha256: sha(header), fault: fault ?? null };
      log.push(entry);
      if (fault === 'drop-before') { entry.outcome = 503; return send(res, 503, { error: 'TEST fault: unavailable before settlement' }); }
      let j; try { j = JSON.parse(Buffer.from(header, 'base64').toString('utf8')); } catch { return send402(res, 'malformed payment header'); }
      const v = await verifyAndSettle(j);
      entry.outcome = v.status;
      if (v.status === 402) return send402(res, v.error);
      if (v.status !== 200) return send(res, v.status, { x402Version: 2, error: v.error, ...(v.code ? { code: v.code } : {}) });
      const payload = { issuer: base, resourceUrl: `${base}/api/x402/witness`, network: v.settlement.network, transaction: v.settlement.transaction, requestSha256: sha(raw), issuedAt: new Date().toISOString(), test: true };
      const receiptId = sha(jcs(payload));
      const member = { info: { receiptId, receiptUrl: `${base}/x402/receipts/${receiptId}`, digest: sha(jcs({ payload, signatures: [] })) } };
      const pr = Buffer.from(JSON.stringify({ ...v.settlement, extensions: { 'delivery-receipt': member } })).toString('base64');
      const out = () => send(res, 200, { seal: { algorithm: 'test-unsigned', content_id: sha(jcs(body.seal_body)) }, payment: v.settlement }, { 'PAYMENT-RESPONSE': pr, 'X-PAYMENT-RESPONSE': pr });
      if (fault?.startsWith('hang-after:')) setTimeout(out, Number(fault.split(':')[1])); else out();
    } catch (e) { send(res, 500, { error: String(e.message || e).slice(0, 300) }); }
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => {
    base = `http://127.0.0.1:${server.address().port}`;
    resolve({ url: `${base}/api/x402/witness`, log, faults, close: () => { server.closeAllConnections?.(); server.close(); } });
  }));
}
