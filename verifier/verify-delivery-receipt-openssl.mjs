#!/usr/bin/env node
// Verify a production x402 delivery-receipt (draft v0.2.1) end to end with ONLY node:crypto (OpenSSL >= 3.5,
// Node >= 24) and a public RPC: no noble, no FractalAI code. Shares nothing with the issuer's implementation.
//
//   node verifier/verify-delivery-receipt-openssl.mjs <receiptId | receipt URL> [--pin-ed25519 HEX] [--pin-ml-dsa-65 HEX]
//
// Pins are SHA-256 of the RAW governance public keys. Without pins the directory is trusted over TLS (stated).
// Exit 0 = every check passed; 1 = a check failed; 2 = input/network error.
import c from 'node:crypto';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const target = args.find((a) => !a.startsWith('--') && !Object.values({ a: opt('--pin-ed25519'), b: opt('--pin-ml-dsa-65') }).includes(a));
if (!target) { console.error('usage: verify-delivery-receipt-openssl.mjs <receiptId|URL> [--pin-ed25519 HEX] [--pin-ml-dsa-65 HEX]'); process.exit(2); }
const url = /^[0-9a-f]{64}$/.test(target) ? `https://fractalai.net.co/x402/receipts/${target}` : target;
const PINS = { ed25519: opt('--pin-ed25519'), 'ml-dsa-65': opt('--pin-ml-dsa-65') };
const RPC = { 'eip155:137': 'https://polygon-bor-rpc.publicnode.com', 'eip155:8453': 'https://mainnet.base.org', 'eip155:42161': 'https://arb1.arbitrum.io/rpc' };

const OID = { ed25519: '06032b6570', 'ml-dsa-65': '0609608648016503040312', 'ml-dsa-87': '0609608648016503040313' };
const L = (n) => n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]);
const T = (t, b) => Buffer.concat([Buffer.from([t]), L(b.length), b]);
const pub = (alg, raw) => c.createPublicKey({ key: T(0x30, Buffer.concat([T(0x30, Buffer.from(OID[alg], 'hex')), T(0x03, Buffer.concat([Buffer.from([0]), raw]))])), format: 'der', type: 'spki' });
const jcs = (x) => x === null || typeof x !== 'object' ? JSON.stringify(x) : Array.isArray(x) ? `[${x.map(jcs).join(',')}]` : `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${jcs(x[k])}`).join(',')}}`;
const sha = (b) => c.createHash('sha256').update(b).digest('hex');
const b64 = (s) => Buffer.from(s, 'base64');
const get = async (u) => { const r = await fetch(u, { headers: { accept: 'application/json' }, redirect: 'error' }); if (!r.ok) throw new Error(`GET ${u} -> HTTP ${r.status}`); return r.json(); };
let failed = 0;
const ok = (name, cond, extra = '') => { console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`); if (!cond) failed++; };
const verify = (alg, raw, msg, sig) => { try { return c.verify(null, msg, pub(alg, raw), sig); } catch { return false; } };

try {
  try { pub('ml-dsa-65', Buffer.alloc(1952, 1)); } catch { console.error(`this runtime cannot verify ML-DSA (OpenSSL ${process.versions.openssl}); use Node >= 24`); process.exit(2); }
  const rcpt = await get(url); const P = rcpt.payload;
  const dir = await get(`${P.issuer}/.well-known/x402-receipt-keys`);
  const id = sha(jcs(P));
  ok('receiptId = SHA-256(JCS(payload))', url.endsWith(id), id);
  ok('directory spec x402-receipt-key-directory/1, nine fields', dir.spec === 'x402-receipt-key-directory/1' && Object.keys(dir).length === 9);
  ok('directory issuer = receipt issuer = resourceUrl origin', dir.issuer === P.issuer && new URL(P.resourceUrl).origin === P.issuer);
  const content = { spec: dir.spec, issuer: dir.issuer, epoch: dir.epoch, prevRoot: dir.prevRoot, publishedAt: dir.publishedAt,
    governanceKeys: [...dir.governanceKeys].sort((a, b) => (a.alg < b.alg ? -1 : 1)), keys: [...dir.keys].sort((a, b) => (a.kid < b.kid ? -1 : 1)) };
  ok('directory root recomputes', sha(jcs(content)) === dir.root, dir.root.slice(0, 16));
  ok('receipt keyDirectoryDigest/epoch = this directory', P.keyDirectoryDigest === dir.root && P.keyDirectoryEpoch === dir.epoch);
  for (const s of dir.signatures) {
    const g = dir.governanceKeys.find((k) => k.alg === s.alg);
    ok(`governance ${s.alg} signature over the directory root`, !!g && verify(s.alg, b64(g.publicKey), Buffer.from(`x402-receipt-key-directory/1\n${dir.root}`), b64(s.signature)));
    if (PINS[s.alg]) ok(`governance ${s.alg} key matches the pin`, !!g && sha(b64(g.publicKey)) === PINS[s.alg].toLowerCase());
  }
  if (!PINS.ed25519 && !PINS['ml-dsa-65']) console.log('NOTE governance keys not pinned: directory trusted over TLS only');
  const msg = Buffer.from(`x402-delivery-receipt/1\n${id}`);
  for (const s of rcpt.signatures) {
    const k = dir.keys.find((x) => x.kid === s.kid && x.alg === s.alg);
    ok(`${s.alg} key listed, active, use x402-delivery-receipt, in force at issuedAt`, !!k && k.status === 'active' && k.use === 'x402-delivery-receipt' && k.notBefore <= P.issuedAt && (k.notAfter == null || k.notAfter >= P.issuedAt));
    ok(`${s.alg} signature over the ${msg.length}-octet message`, !!k && verify(s.alg, b64(k.publicKey), msg, b64(s.signature)));
    const t = Buffer.from(msg); t[t.length - 1] ^= 1;
    ok(`${s.alg} one-bit change rejected`, !!k && !verify(s.alg, b64(k.publicKey), t, b64(s.signature)));
  }
  const rpcUrl = RPC[P.network];
  if (!rpcUrl) console.log(`NOTE no public RPC configured for ${P.network}: settlement not checked`);
  else {
    const res = await (await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [P.transaction] }) })).json();
    const tr = res.result; const log = tr?.logs?.find((l) => parseInt(l.logIndex, 16) === P.logIndex);
    const a = (t) => '0x' + t.slice(26).toLowerCase();
    ok(`settlement tx succeeded on ${P.network}`, tr?.status === '0x1', tr ? `block ${parseInt(tr.blockNumber, 16)}` : 'not found');
    ok('log at logIndex = Transfer(payer -> payTo, amount) of asset', !!log && log.address.toLowerCase() === P.asset.toLowerCase()
      && log.topics[0] === '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
      && a(log.topics[1]) === P.payer.toLowerCase() && a(log.topics[2]) === P.payTo.toLowerCase() && BigInt(log.data) === BigInt(P.amount));
  }
} catch (e) { console.error(`error: ${e.message}`); process.exit(2); }
console.log(failed ? `RESULT: FAIL (${failed})` : 'RESULT: ALL OK', `— node ${process.version}, OpenSSL ${process.versions.openssl}`);
process.exit(failed ? 1 : 0);
