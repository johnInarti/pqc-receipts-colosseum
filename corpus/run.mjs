#!/usr/bin/env node
/**
 * Corpus runner (JavaScript reference). Every implementation of Trust Kernel v2 MUST pass 100 %.
 *   node corpus/run.mjs            offline: every vector in corpus/vectors (manifest-checked)
 *   node corpus/run.mjs --live     also re-verify the live positives against production + public RPCs
 *   node corpus/run.mjs --only ID  run a single vector
 * Refuses an empty corpus, a manifest mismatch, or any vector it cannot evaluate (fail closed).
 */
import { readFileSync, readdirSync } from 'node:fs';
import { verify, parseJsonStrict, sha256hex, oneLine } from '../kernel/src/index.mjs';
import { replayFetch } from './lib/replay.mjs';

const here = (p) => new URL(p, import.meta.url);
const args = process.argv.slice(2);
const only = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;
const json = (p) => parseJsonStrict(readFileSync(here(p), 'utf8'));

export function resolveRefs(v, cache = new Map()) {
  if (Array.isArray(v)) return v.flatMap((x) => {
    const r = resolveRefs(x, cache);
    return x && typeof x === 'object' && !Array.isArray(x) && typeof x.$ref === 'string' && x.$ref.includes('#') && Array.isArray(r) ? r : [r];
  });
  if (v && typeof v === 'object') {
    if (typeof v.$ref === 'string') {
      const [file, frag] = v.$ref.split('#');
      if (!/^fixtures\/[A-Za-z0-9._/-]+\.json$/.test(file) || file.includes('..')) throw new Error(`bad $ref ${v.$ref}`);
      if (!cache.has(file)) cache.set(file, json(`./${file}`));
      const doc = cache.get(file);
      return JSON.parse(JSON.stringify(frag ? doc[frag] : doc));
    }
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolveRefs(x, cache)]));
  }
  return v;
}

const camel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
export function kernelOptions(ctx) {
  const o = ctx.options || {};
  const opts = { now: ctx.now };
  for (const [k, x] of Object.entries(o)) {
    if (x === undefined || x === null) continue;
    if (k === 'policy') opts.policy = Object.fromEntries(Object.entries(x).map(([pk, pv]) => [camel(pk), pv]));
    else if (k === 'anchors' || k === 'trusted_keys') opts[camel(k)] = JSON.stringify(x);
    else opts[camel(k)] = x;
  }
  if (ctx.roots !== undefined) opts.roots = ctx.roots;
  if (ctx.directory !== undefined) opts.directory = JSON.stringify(ctx.directory);
  if (ctx.directory_history !== undefined) opts.directoryHistory = JSON.stringify(ctx.directory_history);
  opts.fetchImpl = replayFetch(ctx.rpc_transcript || []);
  return opts;
}

export function compare(v, expect) {
  const errs = [];
  if (v.valid !== expect.valid) errs.push(`valid ${v.valid} != ${expect.valid}`);
  // spec 2.1: a level absent from expect.levels is expected to be null (not evaluated) — vectors written for
  // spec 2.0 (five levels) keep their meaning; `onchain` is only ever evaluated for kinds with on-chain facts.
  for (const l of ['integrity', 'authentic', 'trusted', 'time_anchored', 'finalized', 'onchain']) {
    const want = expect.levels[l] === undefined ? null : expect.levels[l];
    if (v.levels[l] !== want) errs.push(`${l} ${v.levels[l]} != ${want}`);
  }
  if (expect.trust_basis !== undefined && v.trust_basis !== expect.trust_basis) errs.push(`trust_basis ${v.trust_basis} != ${expect.trust_basis}`);
  if (expect.exit_code !== undefined && v.exit_code !== expect.exit_code) errs.push(`exit_code ${v.exit_code} != ${expect.exit_code}`);
  const got = new Set(v.reasons.map((r) => r.code));
  for (const c of expect.codes || []) if (!got.has(c)) errs.push(`missing reason code ${c}`);
  if (expect.valid === false && v.reasons.length === 0) errs.push('invalid verdict without any reason');
  return errs;
}

async function runOffline() {
  const manifest = json('./manifest.json');
  const files = readdirSync(here('./vectors/')).filter((f) => f.endsWith('.json')).sort();
  const ids = Object.keys(manifest.vectors || {}).sort();
  if (files.length === 0 || ids.length === 0 || manifest.count !== ids.length) throw new Error('empty corpus or manifest count mismatch — refusing to report conformance');
  const fileIds = new Set(files.map((f) => f.slice(0, -5)));
  if (files.length !== ids.length || ids.some((i) => !fileIds.has(i))) throw new Error('vectors/ and manifest.json disagree (missing or extra vector files)');
  let pass = 0; const fails = [];
  for (const id of ids) {
    if (only && id !== only) continue;
    const raw = readFileSync(here(`./vectors/${id}.json`));
    if (sha256hex(raw) !== manifest.vectors[id]) { fails.push([id, ['vector file hash != manifest']]); continue; }
    const vec = resolveRefs(parseJsonStrict(raw.toString('utf8')));
    for (const p of vec.input.prime_json || []) { try { JSON.parse(p); } catch { /* priming only */ } }
    const input = vec.input.receipt_text !== undefined ? vec.input.receipt_text : JSON.stringify(vec.input.receipt);
    let v;
    try { v = await verify(input, kernelOptions(vec.context)); } catch (e) { fails.push([id, [`kernel threw: ${e.message}`]]); continue; }
    const errs = compare(v, vec.expect);
    if (errs.length) fails.push([id, errs, v.reasons]); else pass++;
  }
  return { pass, fails, total: only ? 1 : ids.length };
}

async function runLive() {
  const ID = 'fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee';
  const { boundedFetch } = await import('../kernel/src/index.mjs');
  const receipt = await boundedFetch(`https://fractalai.net.co/api/midas/alerts/receipt/${ID}`);
  const directory = await boundedFetch('https://fractalai.net.co/.well-known/x402-receipt-keys');
  const all = ['integrity', 'authentic', 'trusted', 'time_anchored', 'finalized'];
  const cases = [
    ['LIVE-fe62-pinned-root', { kind: 'midas-alert', directory, expectedId: ID }, { valid: true, levels: { integrity: true, authentic: true, trusted: true, time_anchored: null, finalized: null }, trust_basis: 'pinned-root' }],
    ['LIVE-arbitrum-one', { kind: 'midas-alert', directory, checkAnchors: true, anchors: JSON.stringify([{ chain_id: 42161, tx_hash: '0x37f0254389deed3953aa44333e32eaeb466f28ff41ac9299eb5285599a7a1174', log_index: 5 }]), policy: { require: all } }, { valid: true, levels: { integrity: true, authentic: true, trusted: true, time_anchored: true, finalized: true } }],
    ['LIVE-arc', { kind: 'midas-alert', directory, checkAnchors: true, anchors: JSON.stringify([{ chain_id: 5042, block_number: 24072596 }]), policy: { require: all } }, { valid: true, levels: { integrity: true, authentic: true, trusted: true, time_anchored: true, finalized: true } }],
    ['LIVE-solana-devnet', { kind: 'midas-alert', directory, checkAnchors: true, anchors: JSON.stringify([{ chain: 'solana', cluster: 'devnet', signature: '5U5CQn94ix6Unbjk5ixKoRfyqmQ8HiPttwyssmUdoGdyCQzupnvNgKL3znnqN46UWLoWuhYHqaiFyynro6pP3qXi' }]), policy: { require: all, allowTestnetAnchors: true } }, { valid: true, levels: { integrity: true, authentic: true, trusted: true, time_anchored: true, finalized: true } }],
  ];
  let pass = 0; const fails = [];
  for (const [id, opts, expect] of cases) {
    const v = await verify(receipt, opts);
    const errs = compare(v, expect);
    if (errs.length) fails.push([id, errs, v.reasons]); else pass++;
    console.log(`${errs.length ? 'FAIL' : 'ok  '} ${id}  levels=${JSON.stringify(v.levels)}${v.anchors.length ? '  anchor_time=' + v.anchors.map((a) => a.facts?.time).join(',') : ''}`);
  }
  return { pass, fails, total: cases.length };
}

const isMain = import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  try {
    const r = await runOffline();
    for (const [id, errs, reasons] of r.fails) console.log(`FAIL ${id}: ${errs.join('; ')}${reasons ? `\n     reasons: ${oneLine(JSON.stringify(reasons), 400)}` : ''}`);
    console.log(`corpus: ${r.pass}/${r.total} vectors pass`);
    let ok = r.fails.length === 0 && r.pass === r.total && r.total > 0;
    if (args.includes('--live')) {
      const l = await runLive();
      for (const [id, errs, reasons] of l.fails) console.log(`FAIL ${id}: ${errs.join('; ')} ${oneLine(JSON.stringify(reasons), 300)}`);
      console.log(`live: ${l.pass}/${l.total} pass`);
      ok = ok && l.fails.length === 0;
    }
    process.exit(ok ? 0 : 1);
  } catch (e) {
    console.error(`corpus runner refused: ${e.message}`);
    process.exit(1);
  }
}
