// PoC 6 — conformance/src/check.mjs prints "✅ CONFORMANT" and exits 0 when the vectors directory has
// no vectors (0/0), or when only one profile's vector is present (missing profiles are only a note).
import { mkdtempSync, writeFileSync, copyFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { verdict } from './_common.mjs';
const empty = mkdtempSync(new URL('./tmp-empty-', import.meta.url).pathname);
const one = mkdtempSync(new URL('./tmp-one-', import.meta.url).pathname);
copyFileSync(new URL('../conformance/vectors/sar.json', import.meta.url), one + '/sar.json');
let vuln = false;
for (const d of [empty, one]) {
  const r = spawnSync(process.execPath, ['../conformance/src/check.mjs', d + '/'], { cwd: new URL('.', import.meta.url).pathname, encoding: 'utf8' });
  const last = r.stdout.trim().split('\n').pop();
  vuln = verdict(r.status === 0, `${d.split('/').pop()} → exit ${r.status}: ${last}`) || vuln;
}
process.exit(vuln ? 1 : 0);
