// SPDX-License-Identifier: Apache-2.0
// Minimal x402 v2 "exact" EVM client for FractalAI's LatAm offers. Two asset-transfer methods, both as
// coinbase/x402 specs/schemes/exact/scheme_exact_evm.md defines them:
//   eip3009 — TransferWithAuthorization signed over the TOKEN's EIP-712 domain (USDC, MXNB). Gasless.
//   permit2 — PermitWitnessTransferFrom signed over the Permit2 domain, spender = x402ExactPermit2Proxy,
//             witness.to = payTo (COPM, BRLA, COPW, wCOP, wARS, wBRL, wMXN). Needs a one-time
//             token.approve(Permit2) from the payer (costs native gas once).
import { ethers } from 'ethers';

export const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
export const X402_PERMIT2_PROXY = '0x402085c248EeA27D92E8b30b2C58ed07f9E20001';

export const CHAINS = {
  'eip155:8453': { name: 'Base', chainId: 8453, rpc: 'https://mainnet.base.org', native: 'ETH' },
  'eip155:42161': { name: 'Arbitrum One', chainId: 42161, rpc: 'https://arb1.arbitrum.io/rpc', native: 'ETH' },
  'eip155:137': { name: 'Polygon', chainId: 137, rpc: 'https://polygon-bor-rpc.publicnode.com', native: 'POL' },
  'eip155:480': { name: 'World Chain', chainId: 480, rpc: 'https://worldchain-mainnet.g.alchemy.com/public', native: 'ETH' },
};

// Only used to name USDC, which the server does not list in pricing_latam. Everything else comes from the 402.
const KNOWN = { 'eip155:8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { symbol: 'USDC', currency: 'USD', decimals: 6 } };

export const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
  ],
};
export const PERMIT2_WITNESS_TYPES = {
  PermitWitnessTransferFrom: [
    { name: 'permitted', type: 'TokenPermissions' }, { name: 'spender', type: 'address' },
    { name: 'nonce', type: 'uint256' }, { name: 'deadline', type: 'uint256' }, { name: 'witness', type: 'Witness' },
  ],
  TokenPermissions: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }],
  Witness: [{ name: 'to', type: 'address' }, { name: 'validAfter', type: 'uint256' }],
};

const ERC20 = [
  'function allowance(address,address) view returns (uint256)', 'function balanceOf(address) view returns (uint256)',
  'function approve(address,uint256) returns (bool)', 'function decimals() view returns (uint8)',
  'function authorizationState(address,bytes32) view returns (bool)',
];
const P2 = ['function nonceBitmap(address,uint256) view returns (uint256)'];

/** Decode the 402: PAYMENT-REQUIRED header (base64 JSON, v2) or, failing that, the JSON body. */
export function parseChallenge(headers, bodyText) {
  const h = headers.get('payment-required');
  let challenge = null;
  if (h) { try { challenge = JSON.parse(Buffer.from(h.trim(), 'base64').toString('utf8')); } catch { /* fall back */ } }
  let body = {};
  try { body = JSON.parse(bodyText); } catch { /* not JSON */ }
  challenge ??= body;
  if (!challenge || !Array.isArray(challenge.accepts)) throw new Error('402 without accepts[]');
  return { challenge, pricing: { ...(body.pricing_latam || {}), ...(body.pricing_copm ? { COPM: { symbol: 'COPM', currency: 'COP', ...body.pricing_copm } } : {}) } };
}

const key = (network, asset) => `${network}:${String(asset).toLowerCase()}`;

/** Every payable offer of the 402, labelled with its symbol, currency and the server's own FX note. */
export function listOffers({ challenge, pricing }) {
  const byAsset = {};
  for (const p of Object.values(pricing)) byAsset[key(p.network, p.asset)] = p;
  const out = [];
  for (const a of challenge.accepts) {
    if (a.scheme !== 'exact' || !CHAINS[a.network]) continue;
    const method = a.extra?.assetTransferMethod ?? (a.extra?.settlement ? null : 'eip3009');
    if (method !== 'eip3009' && method !== 'permit2') continue; // e.g. the facilitator-less "txHash" USDC entry
    const p = byAsset[key(a.network, a.asset)] || KNOWN[key(a.network, a.asset)] || {};
    out.push({
      accept: a, method, symbol: p.symbol ?? a.extra?.name ?? '?', currency: p.currency ?? '?',
      decimals: a.extra?.decimals ?? p.decimals, fx: p.fx, label: p.label,
    });
  }
  return out;
}

/** Pick the offer for --token (case-insensitive symbol) and optional --network (CAIP-2 or chain name). */
export function selectOffer(offers, token, network) {
  const t = token.toLowerCase();
  let m = offers.filter((o) => o.symbol.toLowerCase() === t);
  if (network) {
    const n = network.toLowerCase();
    m = m.filter((o) => o.accept.network === network || CHAINS[o.accept.network].name.toLowerCase().replace(/ /g, '') === n.replace(/ /g, ''));
  }
  if (m.length === 0) throw new Error(`the server does not accept ${token}${network ? ' on ' + network : ''} right now. Offered: ${offers.map((o) => `${o.symbol}@${CHAINS[o.accept.network].name}`).join(', ')}`);
  if (m.length > 1) throw new Error(`${token} is offered on several chains (${m.map((o) => o.accept.network).join(', ')}): pass --network`);
  return m[0];
}

export function formatAmount(atomic, decimals) { return decimals == null ? `${atomic} (atomic)` : ethers.formatUnits(atomic, decimals); }

/**
 * Build and sign the payment ONCE. Returns the header value and what it commits to (for logs/state).
 * The signature never leaves this process except inside the header sent to the server.
 */
export async function signPayment(wallet, offer, challenge, now = Math.floor(Date.now() / 1000)) {
  const a = offer.accept;
  const chainId = CHAINS[a.network].chainId;
  const from = await wallet.getAddress();
  const timeout = Math.min(Number(a.maxTimeoutSeconds) || 300, 3600);
  let payload, nonce;
  if (offer.method === 'eip3009') {
    if (!a.extra?.name || !a.extra?.version) throw new Error('eip3009 offer without extra.name/extra.version (EIP-712 domain)');
    nonce = ethers.hexlify(ethers.randomBytes(32));
    const authorization = { from, to: ethers.getAddress(a.payTo), value: a.amount, validAfter: String(now - 600), validBefore: String(now + timeout), nonce };
    const domain = { name: a.extra.name, version: a.extra.version, chainId, verifyingContract: ethers.getAddress(a.asset) };
    const signature = await wallet.signTypedData(domain, EIP3009_TYPES, authorization);
    payload = { signature, authorization };
  } else {
    nonce = BigInt(ethers.hexlify(ethers.randomBytes(31))).toString(); // any uint256; Permit2 nonces are unordered
    const permit2Authorization = {
      from, permitted: { token: ethers.getAddress(a.asset), amount: a.amount }, spender: X402_PERMIT2_PROXY,
      nonce, deadline: String(now + timeout), witness: { to: ethers.getAddress(a.payTo), validAfter: String(now - 600) },
    };
    const signature = await wallet.signTypedData({ name: 'Permit2', chainId, verifyingContract: PERMIT2 }, PERMIT2_WITNESS_TYPES, permit2Authorization);
    payload = { signature, permit2Authorization };
  }
  const body = { x402Version: 2, scheme: 'exact', network: a.network, resource: challenge.resource, accepted: a, payload };
  return { header: Buffer.from(JSON.stringify(body)).toString('base64'), from, nonce, method: offer.method };
}

/** Has this exact authorization already been consumed on-chain? (true = money moved) */
export async function nonceConsumed(provider, offer, from, nonce) {
  if (offer.method === 'eip3009') return new ethers.Contract(offer.accept.asset, ERC20, provider).authorizationState(from, nonce);
  const n = BigInt(nonce);
  const word = await new ethers.Contract(PERMIT2, P2, provider).nonceBitmap(from, n >> 8n);
  return ((word >> (n & 255n)) & 1n) === 1n;
}

export async function readBalances(provider, offer, owner) {
  const t = new ethers.Contract(offer.accept.asset, ERC20, provider);
  const [balance, allowance, decimals] = await Promise.all([
    t.balanceOf(owner), offer.method === 'permit2' ? t.allowance(owner, PERMIT2) : Promise.resolve(null),
    offer.decimals != null ? Promise.resolve(offer.decimals) : t.decimals().then(Number),
  ]);
  return { balance, allowance, decimals };
}

/** One-time token.approve(Permit2, max). Sent by the payer; costs native gas once per token and chain. */
export async function approvePermit2(wallet, offer) {
  const tx = await new ethers.Contract(offer.accept.asset, ERC20, wallet).approve(PERMIT2, ethers.MaxUint256);
  const r = await tx.wait(1, 180_000);
  if (!r || r.status !== 1) throw new Error(`approve reverted (${tx.hash})`);
  return tx.hash;
}

export function decodePaymentResponse(headers) {
  const h = headers.get('payment-response') || headers.get('x-payment-response');
  if (!h) return null;
  try { return JSON.parse(Buffer.from(h, 'base64').toString('utf8')); } catch { return null; }
}
