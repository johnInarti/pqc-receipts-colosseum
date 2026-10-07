/**
 * Kernel unit tests for behaviour that is not expressible as a corpus vector: transport deadlines and caps,
 * load-time self-tests, defensive copies, the engine-unsafe object-input rule, CLI exit codes, and the
 * single-source-of-trust invariant (no other parser / verifier of trust inside the kernel).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  verify, boundedFetch, parseJsonStrict, b64decodeStrict, oneLine, SELF_TEST, BAKED_ROOTS, CODES, EXIT, checkEpoch,
} from '../src/index.mjs';

const fx = (p) => readFileSync(new URL(`../../corpus/fixtures/${p}`, import.meta.url), 'utf8');
const RECEIPT = fx('midas-fe62b072.json');
const DIR = fx('directory-epoch3.json');

function server(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler).listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${s.address().port}/x`, close: () => { s.closeAllConnections?.(); s.close(); } }));
  });
}

test('self-tests ran at load: ML-DSA-65 KAT and strict-parser key self-test pass', () => {
  assert.equal(SELF_TEST.ok, true);
  assert.equal(SELF_TEST.mldsa_kat, true);
  assert.equal(SELF_TEST.strict_json_parser, true);
  assert.equal(typeof SELF_TEST.native_json_key_cache_ok, 'boolean');
});

test('baked roots: governance key verifies the baked checkpoint directory; anchors pinned with code hash', () => {
  const d = parseJsonStrict(DIR);
  assert.equal(d.root, BAKED_ROOTS.directory_checkpoint.root);
  checkEpoch(d, BAKED_ROOTS.governance.public_key_b64);
  assert.equal(BAKED_ROOTS.anchors.evm['42161'].runtime_codehash, '0xe4733ce5c69278cb8072bebfd2500679236551039f896850929d0ceb443f2595');
  assert.ok(Object.isFrozen(BAKED_ROOTS.anchors.evm));
});

test('boundedFetch: a server that stalls mid-body hits ONE hard deadline (headers + body)', async () => {
  const s = await server((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); });
  const t0 = Date.now();
  await assert.rejects(boundedFetch(s.url, { timeoutMs: 400 }), (e) => e.code === CODES.RPC_ERROR && /timeout/.test(e.detail));
  assert.ok(Date.now() - t0 < 3000);
  s.close();
});

test('boundedFetch: deadline still fires when the stall outlasts the transport idle timers (regression)', async () => {
  const s = await server((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); });
  const t0 = Date.now();
  await assert.rejects(boundedFetch(s.url, { timeoutMs: 6000 }), (e) => e.code === CODES.RPC_ERROR && /timeout/.test(e.detail));
  assert.ok(Date.now() - t0 < 9000);
  s.close();
});

test('boundedFetch: non-JSON content-type refused', async () => {
  const s = await server((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('{}'); });
  await assert.rejects(boundedFetch(s.url), (e) => e.code === CODES.RPC_ERROR && /content-type/.test(e.detail));
  s.close();
});

test('boundedFetch: body cap enforced while streaming; redirects refused', async () => {
  const big = await server((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('['.padEnd(5000, ' ') + ']'); });
  await assert.rejects(boundedFetch(big.url, { maxBytes: 1000 }), (e) => e.code === CODES.JSON_TOO_LARGE);
  big.close();
  const redir = await server((req, res) => { res.writeHead(302, { location: 'http://169.254.169.254/latest' }); res.end(); });
  await assert.rejects(boundedFetch(redir.url), (e) => e.code === CODES.RPC_ERROR);
  redir.close();
});

test('boundedFetch: plain http to a non-loopback host is refused', async () => {
  await assert.rejects(boundedFetch('http://example.com/x'), (e) => e.code === CODES.RPC_ERROR && /non-HTTPS/.test(e.detail));
});

test('strict JSON: duplicate keys, lone surrogates, NaN, BOM, depth — rejected with codes', () => {
  const code = (t) => { try { parseJsonStrict(t); return 'ok'; } catch (e) { return e.code; } };
  assert.equal(code('{"a":1,"a":2}'), CODES.JSON_DUPLICATE_KEY);
  assert.equal(code('{"a":"\\ud800"}'), CODES.JSON_LONE_SURROGATE);
  assert.equal(code('{"a":NaN}'), CODES.JSON_INVALID);
  assert.equal(code('\ufeff{}'), CODES.JSON_INVALID);
  assert.equal(code('['.repeat(40) + ']'.repeat(40)), CODES.JSON_TOO_DEEP);
  assert.equal(Object.getPrototypeOf(parseJsonStrict('{"__proto__":{"x":1}}')), null);
  assert.equal({}.x, undefined);
});

test('strict base64: one byte string, one accepted text form', () => {
  assert.deepEqual([...b64decodeStrict('QUJD')], [65, 66, 67]);
  for (const bad of ['QUJD\n', ' QUJD', 'QUI', 'QUJ=', 'QR==', 'QUJD====', 'QU-D']) assert.throws(() => b64decodeStrict(bad), (e) => e.code === CODES.B64_NONCANONICAL);
});

test('defensive copy: mutating the caller objects after verify cannot change the verdict', async () => {
  const dir = parseJsonStrict(DIR);
  const p = verify(RECEIPT, { kind: 'midas-alert', directory: JSON.stringify(dir) });
  dir.keys.length = 0;
  assert.equal((await p).valid, true);
});

test('object input is refused when the engine failed the native JSON key-cache self-test (text input always works)', async () => {
  const obj = JSON.parse(RECEIPT);
  const v = await verify(obj, { kind: 'midas-alert', directory: DIR });
  if (SELF_TEST.native_json_key_cache_ok) assert.equal(v.valid, true);
  else {
    assert.equal(v.valid, false);
    assert.equal(v.reasons[0].code, CODES.ENGINE_UNSAFE_OBJECT_INPUT);
    const v2 = await verify(obj, { kind: 'midas-alert', directory: DIR, allowObjectInput: true });
    assert.equal(v2.valid, true);
    assert.ok(v2.overrides.some((o) => o.startsWith('allowObjectInput')));
  }
});

test('verify never throws on hostile input', async () => {
  for (const x of [null, 42, '', '[]', '{"canonical":{}}', new Uint8Array([0xff, 0xfe]), '{"body":{"schema":1}}']) {
    const v = await verify(x, { kinds: ['midas-alert', 'x402-seal'], directory: DIR });
    assert.equal(v.valid, false);
    assert.ok(v.reasons.length > 0);
  }
  const v = await verify(RECEIPT, { kind: 'midas-alert', directory: DIR, policy: { require: ['nonsense'] } });
  assert.equal(v.valid, false);
});

test('oneLine escapes control, bidi and line-separator characters', () => {
  assert.equal(oneLine('a\nb\u202ec\u2028::set-output'), 'a\\u000ab\\u202ec\\u2028::set-output');
});

test('CLI: exit code per first failed level (valid 0, integrity 10, trusted 12)', () => {
  const cli = new URL('../bin/fractalai-verify.mjs', import.meta.url).pathname;
  const vec = (n) => new URL(`../../corpus/fixtures/${n}`, import.meta.url).pathname;
  const dir = vec('directory-epoch3.json');
  const run = (...a) => spawnSync(process.execPath, [cli, ...a], { encoding: 'utf8', timeout: 60000 });
  assert.equal(run(vec('midas-fe62b072.json'), '--directory', dir).status, EXIT.VALID);
  assert.equal(run(dir, '--directory', dir).status, EXIT.integrity);
  assert.equal(run(vec('midas-fe62b072.json'), '--trusted-key', 'QUJD').status, EXIT.trusted);
  assert.equal(run().status, EXIT.USAGE);
});

test('single source of trust: no native JSON.parse on untrusted input inside kernel/src (selftest primes only)', () => {
  const dir = new URL('../src/', import.meta.url);
  const walk = (u) => readdirSync(u, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(new URL(`${e.name}/`, u)) : [new URL(e.name, u)]));
  for (const f of walk(dir)) {
    const src = readFileSync(f, 'utf8');
    if (f.pathname.endsWith('selftest.mjs')) continue;
    assert.equal(/JSON\.parse\(/.test(src), false, `${f.pathname} uses JSON.parse`);
  }
});

// §8.1: a leading UTF-8 BOM is rejected whether the receipt arrives as text or as raw bytes,
// and a non-UTF-8 network body is a typed JSON_INVALID (never silently repaired).
import { parseJsonStrict as _pjs, boundedFetch as _bf } from '../src/index.mjs';
test('hygiene: BOM rejected as text and as bytes; invalid UTF-8 body rejected', async () => {
  const assertRejects = (fn) => { let code; try { fn(); } catch (e) { code = e.code; } assert.equal(code, 'JSON_INVALID'); };
  assertRejects(() => _pjs('﻿{}'));
  assertRejects(() => _pjs(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])));
  assertRejects(() => _pjs(new Uint8Array([0x7b, 0xff, 0x7d])));
  const body = (bytes) => async () => ({ ok: true, status: 200, headers: new Map([['content-type', 'application/json']]), body: new ReadableStream({ start(c) { c.enqueue(bytes); c.close(); } }) });
  for (const bytes of [new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), new Uint8Array([0x7b, 0xff, 0x7d])]) {
    let code;
    try { const t = await _bf('https://example.invalid/x', { fetchImpl: body(bytes) }); _pjs(t); } catch (e) { code = e.code; }
    assert.equal(code, 'JSON_INVALID');
  }
});
