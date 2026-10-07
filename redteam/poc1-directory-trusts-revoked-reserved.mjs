// PoC 1 — verifyDirectory()/verifyReceiptChain() return ALL keys of a signed directory as trusted,
// ignoring status (revoked / reserved / retiring past not_after) and not_before/not_after windows.
import { buildDirectory, kidForKey } from '../conformance/src/key-directory.mjs';
import { verifyReceiptChain } from '../conformance/src/verify-chain.mjs';
import { ml_dsa65, b64, utf8, keyFromByte, verdict } from './_common.mjs';

const GOV_SEED = '11'.repeat(32);
const active = keyFromByte(1), revoked = keyFromByte(2), reserved = keyFromByte(3), expired = keyFromByte(4);
const entry = (kp, extra) => { const pk = b64(kp.publicKey); return { kid: kidForKey(pk), use: 'x402-receipt', public_key_b64: pk, ...extra }; };
const dir = buildDirectory([
  entry(active, { status: 'active', not_before: 0, not_after: null }),
  entry(revoked, { status: 'revoked', not_before: 0, not_after: 1 }),          // compromised key
  entry(reserved, { status: 'reserved', not_before: null, not_after: null }),  // cold spare, never activated
  entry(expired, { status: 'retiring', not_before: 0, not_after: 1000 }),      // retired in 1970
], GOV_SEED, { epoch: 3 });
const govKey = dir.directory_public_key; // pinned out-of-band in a real deployment

let vuln = false;
for (const [name, kp] of [['revoked', revoked], ['reserved', reserved], ['retiring-expired', expired]]) {
  const sm = `FRACTALAI-x402-served-v1\nverify-agent\n${'ab'.repeat(32)}`;
  const receipt = { domain: 'FRACTALAI-x402-served-v1', route_id: 'verify-agent', digest: 'ab'.repeat(32), signed_message: sm, signature: b64(ml_dsa65.sign(utf8(sm), kp.secretKey)), public_key: b64(kp.publicKey) };
  const r = verifyReceiptChain({ receipt, profile: 'x402-served', directory: dir, governanceKey: govKey });
  vuln = verdict(r.trusted === true, `receipt signed by ${name} key → trusted=${r.trusted} (${r.reason.slice(0, 70)}…)`) || vuln;
}
process.exit(vuln ? 1 : 0);
