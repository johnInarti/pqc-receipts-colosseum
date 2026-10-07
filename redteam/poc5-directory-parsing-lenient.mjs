// PoC 5 — trustedKeysFromDirectory() (used by the verify-anchor CLI) never verifies the directory's
// governance signature/root and is lenient on lifecycle fields: missing status → trusted ("epoch-1
// shape"), not_after given as a string → ignored, not_before in the future → ignored, `use` ignored.
import { trustedKeysFromDirectory } from '../verifier/src/verify-anchor.mjs';
import { verdict } from './_common.mjs';
const now = 1_800_000_000;
const dir = { spec: 'FRACTALAI-key-directory-v1', epoch: 99, /* NO signature, NO root */ keys: [
  { public_key_b64: 'NO_STATUS' },
  { public_key_b64: 'NOT_AFTER_STRING', status: 'retiring', not_after: '1970-01-01' },
  { public_key_b64: 'NOT_YET_VALID', status: 'active', not_before: now + 10 ** 6 },
  { public_key_b64: 'GOVERNANCE_USE', status: 'active', use: 'key-directory-governance' },
] };
const t = trustedKeysFromDirectory(dir, now);
let vuln = false;
for (const k of dir.keys) vuln = verdict(t.includes(k.public_key_b64), `unsigned directory, key ${k.public_key_b64} → trusted=${t.includes(k.public_key_b64)}`) || vuln;
process.exit(vuln ? 1 : 0);
