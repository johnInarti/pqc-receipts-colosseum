#!/usr/bin/env node
// Verify one FractalAI MIDAS signed alert end to end — every decision by Trust Kernel v2:
// the receipt is bound to the id you asked for, the signed message is REBUILT (never read from the receipt),
// unsigned fields (facts, emitted_at, snapshot) must match what was signed, and the key directory must verify
// against the PINNED governance key + epoch checkpoint baked in kernel/trust-roots.json (TLS is transport only).
// Fetches have a hard deadline covering headers AND body and a 2 MiB cap.
// usage: node verify-midas-alert.mjs [receipt_id] [--json]   (default: the public receipt fe62b072…)
// exit: 0 valid · 10 integrity · 11 authentic · 12 trusted · 3 could not fetch
import { verify, boundedFetch, oneLine, safeJson, EXIT } from '@fractalai/pqc-trust-kernel';

const args = process.argv.slice(2);
const id = args.find((a) => !a.startsWith('--')) || 'fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee';
if (!/^[0-9a-f]{64}$/.test(id)) { console.error('receipt id must be 64 lowercase hex'); process.exit(EXIT.USAGE); }
const base = process.env.FRACTALAI_BASE || 'https://fractalai.net.co';
const timeoutMs = Math.min(20000, Math.max(500, Number(process.env.FRACTALAI_FETCH_TIMEOUT_MS) || 20000));

let receipt, directory;
try {
  receipt = await boundedFetch(`${base}/api/midas/alerts/receipt/${id}`, { timeoutMs, headers: { accept: 'application/json' } });
  directory = await boundedFetch(`${base}/.well-known/x402-receipt-keys`, { timeoutMs, headers: { accept: 'application/json' } });
} catch (e) {
  console.error(`could not fetch: ${oneLine(e.detail ?? e.message)}`);
  process.exit(EXIT.INPUT);
}
const v = await verify(receipt, { kind: 'midas-alert', expectedId: id, directory });
if (args.includes('--json')) console.log(safeJson(v));
else {
  console.log(safeJson({ levels: v.levels, trust_basis: v.trust_basis, key: v.key, directory: v.directory, reasons: v.reasons }));
  console.log(v.valid
    ? `VALID (ML-DSA-65 signature over the rebuilt message; key ${v.key.status} at the signed time in directory epoch ${v.directory.epoch}, verified against pinned roots)`
    : `INVALID — ${oneLine(v.reasons.map((r) => r.code).join(', '))}`);
}
process.exit(v.exit_code);
