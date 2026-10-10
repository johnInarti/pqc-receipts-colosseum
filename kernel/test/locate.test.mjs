import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fetchLegacyDirectory, LEGACY_DIRECTORY_PATH } from '../src/index.mjs';

const LEGACY = readFileSync(new URL('../checkpoint-directory.json', import.meta.url), 'utf8');
const SPEC = JSON.stringify({ spec: 'x402-receipt-key-directory/1', issuer: 'https://fractalai.net.co', epoch: 1 });
const ORIGIN = 'https://fractalai.net.co';
const OLD = `${ORIGIN}/.well-known/x402-receipt-keys`;
const NEW = `${ORIGIN}${LEGACY_DIRECTORY_PATH}`;

const fake = (routes) => {
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(String(url));
    const body = routes[String(url)];
    if (body === undefined) return new Response('not found', { status: 404 });
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { fetchImpl, seen };
};

test('legacy chain still at the old path: used as is', async () => {
  const f = fake({ [OLD]: LEGACY });
  const r = await fetchLegacyDirectory(OLD, { fetchImpl: f.fetchImpl });
  assert.equal(r.text, LEGACY); assert.equal(r.relocated, false); assert.deepEqual(f.seen, [OLD]);
});

test('old path now serves the spec format: relocates to the legacy path on the same origin', async () => {
  const f = fake({ [OLD]: SPEC, [NEW]: LEGACY });
  const r = await fetchLegacyDirectory(OLD, { fetchImpl: f.fetchImpl });
  assert.equal(r.text, LEGACY); assert.equal(r.relocated, true); assert.equal(r.url, NEW);
});

test('old path 404 (moved, nothing in its place): relocates', async () => {
  const f = fake({ [NEW]: LEGACY });
  assert.equal((await fetchLegacyDirectory(OLD, { fetchImpl: f.fetchImpl })).url, NEW);
});

test('the spec-format document is never accepted as a FractalAI epoch', async () => {
  const f = fake({ [OLD]: SPEC, [NEW]: SPEC });
  await assert.rejects(fetchLegacyDirectory(OLD, { fetchImpl: f.fetchImpl }), /DIRECTORY_INVALID|is a FRACTALAI-key-directory-v1/);
});

test('a forged document cannot redirect the verifier off-origin (pointers are ignored)', async () => {
  const forged = JSON.stringify({ spec: 'x402-receipt-key-directory/1', legacy: 'https://evil.example/.well-known/fractalai-key-directory' });
  const f = fake({ [OLD]: forged, [NEW]: LEGACY });
  const r = await fetchLegacyDirectory(OLD, { fetchImpl: f.fetchImpl });
  assert.ok(f.seen.every((u) => u.startsWith(ORIGIN))); assert.equal(r.url, NEW);
});

test('relocation stays on the origin of the URL it was given', async () => {
  const f = fake({ 'https://issuer.example/.well-known/fractalai-key-directory': LEGACY });
  const r = await fetchLegacyDirectory('https://issuer.example/.well-known/x402-receipt-keys', { fetchImpl: f.fetchImpl });
  assert.equal(r.url, 'https://issuer.example/.well-known/fractalai-key-directory');
});

test('given the legacy path directly and it is not legacy: error, no loop', async () => {
  const f = fake({ [NEW]: SPEC });
  await assert.rejects(fetchLegacyDirectory(NEW, { fetchImpl: f.fetchImpl }));
  assert.deepEqual(f.seen, [NEW]);
});
