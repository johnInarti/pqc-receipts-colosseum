/**
 * verify-chain — the capstone: ONE call that answers "can I trust this agent receipt, end to end?"
 * It composes the whole trust chain the red-teams hardened, so an auditor / bank / counterparty runs a
 * single function instead of wiring three modules and (crucially) instead of forgetting the key-provenance
 * step that a bare signature check omits:
 *
 *   1. DIRECTORY   — verifyDirectory: the key directory is ML-DSA-65-signed by a pinned governance key
 *                    AND (when given) its root matches the on-chain anchoredRoot → yields trustedKeys.
 *   2. RECEIPT     — verifyProfile: the receipt's ML-DSA-65 signature verifies over its canonical bytes
 *                    AND its key ∈ trustedKeys (fail-closed; a self-signed forgery is rejected).
 *   3. WATCHTOWER  — (optional) auditHistory over observed directory epochs shows no CRITICAL/HIGH
 *                    (no equivocation / rollback / silent key substitution / anchor divergence).
 *
 * trusted === all supplied steps pass. Pure, offline, @noble only. This is what the standards inserts
 * mean by "verify it yourself, talking to nobody" — now as a single end-to-end statement.
 */
import { verifySync } from '@fractalai/pqc-trust-kernel';
import { verifyProfile } from './profiles.mjs';
import { verifyDirectory } from './key-directory.mjs';
import { auditHistory } from './watchtower.mjs';

/**
 * @param input {
 *   receipt, profile,                       // the receipt + its profile id (x402-served|sar|acp-verdict|jose-ml-dsa-65|vc-di-ml-dsa-65)
 *   directory,                              // the signed key directory (from /.well-known/x402-receipt-keys)
 *   governanceKey?, anchoredRoot?,          // trust roots for the directory (pin the governance key and/or the on-chain root)
 *   watchtowerHistory?, watchtowerOpts?,    // optional: history of directory observations to audit for equivocation etc.
 * }
 * @returns { trusted, reason, steps:{ directory, receipt, watchtower } }
 */
export function verifyReceiptChain(input) {
  const steps = {};

  const warnings = [];
  const pinned = !!input.governanceKey, anchored = !!input.anchoredRoot, watched = !!input.watchtowerHistory;
  const posture = () => ({ pinned, anchored, watched });

  // 0) The receipt's `.profile` field is NOT part of any signed message (attacker-editable). If present it
  //    must match the declared profile, else a downstream reader of receipt.profile is misled (red-team LOW).
  if (input.receipt && input.receipt.profile != null && input.receipt.profile !== input.profile) {
    return { trusted: false, reason: `receipt.profile '${input.receipt.profile}' != declared profile '${input.profile}' (unauthenticated field mismatch)`, ...posture(), steps };
  }
  // Confused-deputy guard (red-team MEDIUM): governanceKey/anchoredRoot MUST be pinned OUT-OF-BAND — never
  // taken from the same directory response. If the only "pin" is the directory's own signer and there is no
  // independent anchor, the pin pins nothing; warn loudly (still fail-closed downstream, but flag it).
  if (pinned && !anchored && input.directory && input.governanceKey === input.directory.directory_public_key) {
    warnings.push('governanceKey equals the directory\'s own signer and no independent anchoredRoot was given — the pin is self-certifying; supply an on-chain anchoredRoot read independently');
  }

  // 1) DIRECTORY — establishes which keys are authentic (fail-closed: needs governanceKey or anchoredRoot).
  const d = verifyDirectory(input.directory || {}, { governanceKey: input.governanceKey, anchoredRoot: input.anchoredRoot, at: input.at });
  steps.directory = d;
  if (!d.valid) return { trusted: false, reason: `directory not trusted: ${d.reason}`, ...posture(), warnings, steps };

  // 2) RECEIPT — FractalAI kinds go straight to the kernel (lifecycle at the SIGNED time, use<->domain
  //    binding); third-party profiles get the keys the kernel authorizes NOW from the verified directory.
  const KIND = { 'x402-served': 'served-proof', 'acp-verdict': 'acp-verdict' };
  let r;
  if (KIND[input.profile]) {
    const kv = verifySync(JSON.stringify(input.receipt ?? null), { kind: KIND[input.profile], directory: JSON.stringify(input.directory), ...(input.governanceKey ? { governanceKey: input.governanceKey } : {}), ...(input.anchoredRoot && !input.governanceKey ? { allowTlsDirectory: true } : {}) });
    r = { valid: kv.valid, signatureValid: kv.levels.authentic, keyTrusted: kv.levels.trusted, reason: kv.valid ? 'authentic (Trust Kernel v2)' : kv.reasons.map((x) => `${x.code}: ${x.detail}`).join(' | '), verdict: kv };
  } else {
    r = verifyProfile(input.profile, input.receipt, { trustedKeys: d.trustedKeys });
  }
  steps.receipt = r;
  if (!r.valid) return { trusted: false, reason: `receipt not authentic: ${r.reason}`, ...posture(), warnings, steps };

  // 3) WATCHTOWER — optional non-equivocation / continuity audit. Thread the anchor so the watchtower
  //    treats a matching on-chain root as an equivalent trust root (red-team LOW: keep composition monotone).
  if (watched) {
    const w = auditHistory(input.watchtowerHistory, { governanceKey: input.governanceKey, anchoredRoot: input.anchoredRoot, ...(input.watchtowerOpts || {}) });
    steps.watchtower = w;
    if (!w.ok) return { trusted: false, reason: `watchtower flagged the directory: ${(w.alerts.find((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH') || {}).code || 'anomaly'}`, ...posture(), warnings, steps };
  }

  // Success attestation built from what ACTUALLY ran (red-team HIGH: no over-claiming "anchored"/"watchtower").
  const reason = 'end-to-end trusted: receipt signed by a key in a directory '
    + (pinned ? 'signed by the pinned governance key' : 'whose root matches the on-chain anchor')
    + (anchored ? ' and anchored on-chain' : ' (NO independent on-chain anchor supplied)')
    + (watched ? '; watchtower found the history consistent' : '; NO watchtower audit was run');
  return { trusted: true, reason, ...posture(), warnings, steps };
}
