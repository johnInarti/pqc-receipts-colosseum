/**
 * Key lifecycle decision (spec/TRUST-KERNEL.md §6.3). Evaluated at the SIGNED time of the receipt
 * (or, for kinds that sign no time, at verification time and only for `active` keys). Pure function.
 *
 *   reserved            → never authorizes anything
 *   active              → not_before ≤ T ≤ (not_after ?? ∞)
 *   retiring | retired  → not_before ≤ T ≤ not_after   (not_after REQUIRED)
 *   revoked             → only if revoked_at is set AND a consensus time proof shows the signed bytes
 *                         existed before revoked_at (anchor_time < revoked_at) AND T ≤ anchor_time + skew.
 *                         A key revoked for compromise can sign any `emitted_at` it likes, so the signed
 *                         time alone can never rescue a revoked key.
 *   use                 → must be one of the kind's allowed uses (domain table)
 */
import { C } from './codes.mjs';

/**
 * @param {object} key        directory entry (already structurally validated)
 * @param {object} p
 * @param {string[]} p.uses   uses allowed by the kind
 * @param {number|null} p.signedTime   signed time (unix s) or null when the kind signs no time
 * @param {number} p.now      verification time (unix s)
 * @param {number|null} p.anchorTime   earliest consensus-verified anchor time, or null
 * @param {number} p.skew     allowed clock skew (s)
 * @returns {{ ok:boolean, code?:string, detail:string, evaluated_at:number, time_basis:'signed'|'verification-time'|'anchor' }}
 */
export function keyAuthorizes(key, { uses, signedTime, now, anchorTime, skew }) {
  const basis = signedTime === null ? 'verification-time' : 'signed';
  const T = signedTime === null ? now : signedTime;
  const R = (ok, code, detail, time_basis = basis) => ({ ok, code, detail, evaluated_at: T, time_basis });
  if (!uses.includes(key.use)) return R(false, C.KEY_USE_MISMATCH, `key use '${key.use}' does not authorize this kind (allowed: ${uses.join(', ') || 'none'})`);
  if (signedTime !== null && signedTime > now + skew) return R(false, C.SIGNED_TIME_IN_FUTURE, `signed time ${signedTime} is after verification time ${now} (+${skew}s)`);
  const nb = key.not_before ?? null, na = key.not_after ?? null;
  switch (key.status) {
    case 'reserved':
      return R(false, C.KEY_STATUS_RESERVED, 'key is reserved (never activated)');
    case 'active':
      if (nb === null) return R(false, C.KEY_WINDOW_MALFORMED, 'active key without not_before');
      if (T < nb) return R(false, C.KEY_NOT_YET_VALID, `T=${T} < not_before ${nb}`);
      if (na !== null && T > na) return R(false, C.KEY_EXPIRED, `T=${T} > not_after ${na}`);
      return R(true, undefined, 'active key inside its window');
    case 'retiring':
    case 'retired':
      if (signedTime === null) return R(false, C.KEY_NEEDS_SIGNED_TIME, `a ${key.status} key only authorizes receipts that carry a signed time`);
      if (nb === null || na === null) return R(false, C.KEY_WINDOW_MALFORMED, `${key.status} key without not_before/not_after`);
      if (T < nb) return R(false, C.KEY_NOT_YET_VALID, `T=${T} < not_before ${nb}`);
      if (T > na) return R(false, C.KEY_EXPIRED, `T=${T} > not_after ${na}`);
      return R(true, undefined, `${key.status} key, signed time inside its window`);
    case 'revoked': {
      const ra = key.revoked_at ?? null;
      if (ra === null) return R(false, C.KEY_REVOKED, 'key revoked without revoked_at — nothing it signed can be trusted');
      if (signedTime === null) return R(false, C.KEY_REVOKED, 'revoked key and the kind signs no time');
      if (anchorTime === null) return R(false, C.KEY_REVOKED, `key revoked at ${ra}; signed time alone cannot prove pre-revocation existence — needs a consensus time anchor before ${ra}`);
      if (anchorTime >= ra) return R(false, C.KEY_REVOKED, `earliest anchor ${anchorTime} is not before revocation ${ra}`);
      if (nb === null || T < nb) return R(false, C.KEY_NOT_YET_VALID, `T=${T} < not_before ${nb}`);
      if (na !== null && T > na) return R(false, C.KEY_EXPIRED, `T=${T} > not_after ${na}`);
      if (T > anchorTime + skew) return R(false, C.ANCHOR_FORWARD_DATED, `signed time ${T} after anchor ${anchorTime}`);
      return { ok: true, detail: `revoked at ${ra}, but anchored at ${anchorTime} (before revocation)`, evaluated_at: anchorTime, time_basis: 'anchor' };
    }
    default:
      return R(false, C.KEY_STATUS_UNKNOWN, `unknown status ${JSON.stringify(key.status)}`);
  }
}
