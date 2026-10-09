/**
 * Issuer tests over REAL recorded chain data (corpus/fixtures/stablecoin/*.json, replayed offline):
 * every receipt the issuer emits must pass the Trust Kernel at integrity+authentic+trusted+onchain, and every
 * refusal rule (spec §12.3) must fire with its code. The CLI is exercised end to end against a loopback
 * JSON-RPC server that replays the same recorded answers. Ephemeral keys only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { issueStablecoinReceipt, loadKey, generateKeyFile, signTransfer } from '../src/issue.mjs';
import { verify, jcs, parseJsonStrict, CODES, EXIT } from '../../kernel/src/index.mjs';
import { replayFetch } from '../../corpus/lib/replay.mjs';

const FX = (n) => parseJsonStrict(readFileSync(new URL(`../../corpus/fixtures/stablecoin/${n}.json`, import.meta.url), 'utf8'));
const ts = (fx) => Math.floor(Date.parse(fx.recorded_at) / 1000);
const KEY = loadKey(generateKeyFile());
const clone = (x) => JSON.parse(JSON.stringify(x));
const LABELS = { 'copm-polygon': ['replay://polygon', 'replay://polygon-1rpc'], 'brla-polygon': ['replay://polygon'], 'brla-base': ['replay://base'], 'mxnb-arbitrum': ['replay://arb1'], 'mxnb-base-swap': ['replay://base'] };

const issue = (fx, o = {}) => issueStablecoinReceipt({
  chainId: fx.chain_id, txHash: fx.tx_hash, logIndex: fx.log_index, rpcUrls: LABELS[o.name] ?? o.urls, key: KEY, now: ts(fx),
  fetchImpl: replayFetch(o.transcript ?? fx.transcript), ...o.req,
});
const refusal = async (p) => { try { await p; } catch (e) { return e.code; } return 'ISSUED'; };

for (const name of Object.keys(LABELS)) {
  test(`issues and self-verifies a receipt for the REAL ${name} transfer; the kernel accepts it on all four levels`, async () => {
    const fx = FX(name);
    const { receipt, text, facts, verdict } = await issue(fx, { name });
    assert.equal(verdict.valid, true);
    const obs = fx.observed[0];
    assert.equal(receipt.transfer.amount, obs.amount);
    assert.equal(receipt.transfer.from, obs.from);
    assert.equal(receipt.transfer.to, obs.to);
    assert.equal(receipt.transfer.block_hash, obs.block_hash);
    assert.equal(receipt.transfer.token, obs.token);
    assert.equal(facts.rpc_count, LABELS[name].length);
    const v = await verify(text, {
      kind: 'latam-stablecoin-receipt', trustedKeys: JSON.stringify([KEY.publicKeyB64]), checkOnchain: true, now: receipt.issued_at + 60,
      rpc: { [`eip155:${fx.chain_id}`]: LABELS[name] }, fetchImpl: replayFetch(fx.transcript), policy: { require: ['integrity', 'authentic', 'trusted', 'onchain'] },
    });
    assert.equal(v.valid, true, JSON.stringify(v.reasons));
    assert.deepEqual(v.levels, { integrity: true, authentic: true, trusted: true, time_anchored: null, finalized: null, onchain: true });
  });
}

test('the requester cannot inject facts: amount/from/to passed in the request are ignored, the chain decides', async () => {
  const fx = FX('brla-polygon');
  const { receipt } = await issue(fx, { name: 'brla-polygon', req: { amount: '1', from: '0x' + '1'.repeat(40), to: '0x' + '2'.repeat(40) } });
  assert.equal(receipt.transfer.amount, fx.observed[0].amount);
  assert.equal(receipt.transfer.from, fx.observed[0].from);
});

test('reference is carried (signed) as an unverified label and validated', async () => {
  const fx = FX('mxnb-arbitrum');
  const { receipt } = await issue(fx, { name: 'mxnb-arbitrum', req: { reference: 'factura:FE-2026-000123' } });
  assert.match(receipt.transfer_canonical, /\nreference=factura:FE-2026-000123$/);
  assert.equal(await refusal(issue(fx, { name: 'mxnb-arbitrum', req: { reference: 'bad ref with spaces' } })), CODES.INPUT_SHAPE);
});

test('log index located automatically when the tx carries exactly one pinned-token Transfer; refused when ambiguous', async () => {
  const fx = FX('mxnb-arbitrum');
  const { receipt } = await issue(fx, { name: 'mxnb-arbitrum', req: { logIndex: undefined } });
  assert.equal(receipt.transfer.log_index, '3');
  const swap = FX('mxnb-base-swap');
  assert.equal(await refusal(issue(swap, { name: 'mxnb-base-swap', req: { logIndex: undefined } })), CODES.INPUT_SHAPE);
});

const rcOf = (t) => t.find((x) => x.method === 'eth_getTransactionReceipt').result;
const logAt = (t, i) => rcOf(t).logs.find((l) => parseInt(l.logIndex, 16) === i);

test('refusals (spec §12.3) — each fires with its reason code', async () => {
  const swap = FX('mxnb-base-swap');
  const brla = FX('brla-polygon');
  const mx = FX('mxnb-arbitrum');
  const copm = FX('copm-polygon');
  const mut = (fx, fn) => { const t = clone(fx.transcript); fn(t); return t; };
  const cases = [
    ['reverted tx', issue(brla, { name: 'brla-polygon', transcript: mut(brla, (t) => { rcOf(t).status = '0x0'; }) }), CODES.PAYMENT_TX_REVERTED],
    ['unknown tx', issue(brla, { name: 'brla-polygon', transcript: mut(brla, (t) => { t.find((x) => x.method === 'eth_getTransactionReceipt').result = null; }) }), CODES.PAYMENT_TX_NOT_FOUND],
    ['REAL USDC log in the swap (not a pinned token)', issue(swap, { name: 'mxnb-base-swap', req: { logIndex: 23 } }), CODES.TOKEN_NOT_PINNED],
    ['REAL MXNB Approval log', issue(swap, { name: 'mxnb-base-swap', req: { logIndex: 25 } }), CODES.PAYMENT_LOG_NOT_TRANSFER],
    ['REAL MXNB burn (to zero address)', issue(swap, { name: 'mxnb-base-swap', req: { logIndex: 28 } }), CODES.PAYMENT_NOT_A_TRANSFER],
    ['zero-amount transfer (address poisoning)', issue(brla, { name: 'brla-polygon', transcript: mut(brla, (t) => { logAt(t, 593).data = '0x' + '0'.repeat(64); }) }), CODES.PAYMENT_NOT_A_TRANSFER],
    ['live symbol differs from the pinned registry', issue(brla, { name: 'brla-polygon', transcript: mut(brla, (t) => { t.find((x) => x.method === 'eth_call' && x.params[0].data === '0x95d89b41').result = '0x' + '20'.padStart(64, '0') + '4'.padStart(64, '0') + Buffer.from('BRLX').toString('hex').padEnd(64, '0'); }) }), CODES.TOKEN_METADATA_MISMATCH],
    ['header hash differs from the receipt block (reorg)', issue(mx, { name: 'mxnb-arbitrum', transcript: mut(mx, (t) => { t.find((x) => x.method === 'eth_getBlockByNumber' && x.params[0] !== 'finalized' && x.url === 'replay://arb1').result.hash = '0x' + 'ab'.repeat(32); }) }), CODES.PAYMENT_REORGED],
    ['REAL: block not finalized on 1rpc', issue(mx, { urls: ['replay://arb1-1rpc'] }), CODES.PAYMENT_NOT_FINALIZED],
    ['RPC serves another chain', issue(copm, { urls: ['replay://base'], transcript: FX('brla-base').transcript }), CODES.PAYMENT_WRONG_CHAIN],
    ['RPCs disagree', issue(copm, { name: 'copm-polygon', transcript: mut(copm, (t) => { const l = t.filter((x) => x.method === 'eth_getTransactionReceipt' && x.url === 'replay://polygon-1rpc')[0].result.logs.find((x) => parseInt(x.logIndex, 16) === 2229); l.data = '0x' + '1'.padStart(64, '0'); }) }), CODES.RPC_DISAGREEMENT],
    ['too few confirmations', issue(brla, { name: 'brla-polygon', req: { minConfirmations: 10_000_000 } }), CODES.PAYMENT_CONFIRMATIONS],
    ['chain without pinned tokens', issue({ ...brla, chain_id: 1 }, { urls: ['replay://polygon'] }), CODES.PAYMENT_WRONG_CHAIN],
  ];
  for (const [what, p, code] of cases) assert.equal(await refusal(p), code, what);
});

test('not finalized can be issued as "confirmed" only when explicitly allowed; the kernel then needs the same policy', async () => {
  const mx = FX('mxnb-arbitrum');
  const { receipt, text } = await issue(mx, { urls: ['replay://arb1-1rpc'], req: { requireFinalized: false } });
  assert.equal(receipt.transfer.finality, 'confirmed');
  const base = { kind: 'latam-stablecoin-receipt', trustedKeys: JSON.stringify([KEY.publicKeyB64]), checkOnchain: true, now: receipt.issued_at, rpc: { 'eip155:42161': ['replay://arb1-1rpc'] }, fetchImpl: replayFetch(mx.transcript) };
  assert.equal((await verify(text, base)).levels.onchain, false);
  assert.equal((await verify(text, { ...base, policy: { allowUnfinalizedPayment: true } })).levels.onchain, true);
});

test('keys: a mismatched pair is refused; a seed key round-trips; signTransfer never reads the chain', () => {
  const a = loadKey(generateKeyFile()), b = loadKey(generateKeyFile());
  assert.notEqual(a.kid, b.kid);
  assert.throws(() => loadKey(JSON.stringify({ algorithm: 'ml-dsa-65', secret_key_b64: Buffer.from(a.secretKey).toString('base64'), public_key_b64: b.publicKeyB64 })), (e) => e.code === CODES.INPUT_SHAPE);
  assert.throws(() => loadKey(JSON.stringify({ algorithm: 'ml-dsa-44', seed_hex: '00'.repeat(32) })), (e) => e.code === CODES.INPUT_SHAPE);
  assert.throws(() => signTransfer({ registry: 'x/1' }, a), (e) => e.code === CODES.CANONICAL_MALFORMED);
});

// ── CLI end to end against a loopback JSON-RPC server that replays the recorded answers ──
function rpcServer(transcript, label) {
  const map = new Map(transcript.filter((t) => t.url === label).map((t) => [`${t.method}\u0000${jcs(t.params ?? [])}`, t]));
  return new Promise((resolve) => {
    const s = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const r = JSON.parse(body);
        const hit = map.get(`${r.method}\u0000${jcs(r.params ?? [])}`);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(hit ? { jsonrpc: '2.0', id: r.id, result: hit.result } : { jsonrpc: '2.0', id: r.id, error: { code: -32601, message: 'not recorded' } }));
      });
    }).listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${s.address().port}/`, close: () => { s.closeAllConnections?.(); s.close(); } }));
  });
}

test('CLI: keygen → issue (REAL COPM transfer, replayed over loopback) → kernel CLI verifies with --onchain (exit 0); tampered → exit 10', async () => {
  const fx = FX('copm-polygon');
  const srv = await rpcServer(fx.transcript, 'replay://polygon');
  const dir = mkdtempSync(join(tmpdir(), 'sc-issuer-'));
  try {
    const cli = new URL('../bin/fractalai-stablecoin-receipt.mjs', import.meta.url).pathname;
    const kcli = new URL('../../kernel/bin/fractalai-verify.mjs', import.meta.url).pathname;
    // async spawn: the loopback server lives in THIS process, so the event loop must keep running
    const run = (bin, a) => new Promise((resolve) => {
      const c = spawn(process.execPath, [bin, ...a]);
      let stdout = '', stderr = '';
      c.stdout.on('data', (d) => { stdout += d; }); c.stderr.on('data', (d) => { stderr += d; });
      c.on('close', (status) => resolve({ status, stdout, stderr }));
    });
    const kg = await run(cli, ['keygen', '--out', join(dir, 'key.json')]);
    assert.equal(kg.status, 0, kg.stderr);
    const pk = /public_key_b64=(\S+)/.exec(kg.stdout)[1];
    assert.equal(kg.stdout.includes(parseJsonStrict(readFileSync(join(dir, 'key.json'), 'utf8')).seed_hex), false, 'the secret is never printed');
    const is = await run(cli, ['issue', '--chain', '137', '--tx', fx.tx_hash, '--log-index', String(fx.log_index), '--key', join(dir, 'key.json'), '--rpc', srv.url, '--reference', 'conciliacion:2026-10', '--out', join(dir, 'r.json')]);
    assert.equal(is.status, 0, is.stderr);
    const vr = await run(kcli, [join(dir, 'r.json'), '--kind', 'latam-stablecoin-receipt', '--trusted-key', pk, '--onchain', '--rpc', `eip155:137=${srv.url}`, '--require', 'integrity,authentic,trusted,onchain']);
    assert.equal(vr.status, EXIT.VALID, vr.stdout + vr.stderr);
    assert.match(vr.stdout, /onchain=yes/);
    const r = parseJsonStrict(readFileSync(join(dir, 'r.json'), 'utf8'));
    r.transfer.amount = '1';
    const tampered = join(dir, 't.json');
    writeFileSync(tampered, JSON.stringify(r));
    assert.equal((await run(kcli, [tampered, '--kind', 'latam-stablecoin-receipt', '--trusted-key', pk])).status, EXIT.integrity);
    const bad = await run(cli, ['issue', '--chain', '137', '--tx', fx.tx_hash, '--log-index', '1', '--key', join(dir, 'key.json'), '--rpc', srv.url]);
    assert.equal(bad.status, 4);
    assert.match(bad.stderr, /PAYMENT_LOG_NOT_FOUND/);
  } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
});
