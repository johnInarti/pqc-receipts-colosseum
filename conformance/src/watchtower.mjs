/**
 * Watchtower — the off-chain monitor the trust model needs (and FractalCheckpoint.sol explicitly calls
 * for). The signed, anchorable key directory (key-directory.mjs) makes tampering/equivocation
 * DETECTABLE; the watchtower is what actually DETECTS it, by auditing a HISTORY of observations over
 * time (directory snapshots + the on-chain anchored root) and raising alerts.
 *
 * What it catches (each with a severity):
 *  - CRITICAL bad-signature / root-mismatch        : a directory whose governance signature fails or
 *                                                    whose root doesn't recompute (verifyDirectory).
 *  - CRITICAL equivocation                          : the SAME epoch observed with DIFFERENT roots
 *                                                    (split view — different keys shown to different people).
 *  - CRITICAL anchor-divergence                     : directory.root != the on-chain anchoredRoot.
 *  - HIGH governance-key-change                      : the signing (governance) key changed (takeover?).
 *  - HIGH epoch-rollback                             : an epoch lower than one already seen (rewind).
 *  - HIGH chain-break                                : epoch N+1's prev_root != epoch N's observed root.
 *  - HIGH key-removed                                : a kid present earlier is gone later (append-only broken).
 *  - MEDIUM anchor-lag / operator-silent            : latest directory root not reflected on-chain / no
 *                                                    new observation for too long (liveness).
 * Pure, offline, deterministic. @noble only (via verifyDirectory). Feed it observations from any source.
 */
import { verifyDirectory } from './key-directory.mjs';

const A = (severity, code, detail) => ({ severity, code, detail });

/**
 * Audit a time-ordered history of observations.
 * @param observations Array<{ at:number, directory:<signed dir>, anchoredRoot?:string|null }>
 * @param opts { governanceKey?:string (pin), maxObservationGap?:number (liveness), maxAnchorLag?:number }
 * @returns { alerts: Alert[], ok:boolean, seenEpochs:number, keysEverSeen:number }
 */
export function auditHistory(observations, opts = {}) {
  const alerts = [];
  // State — seeded from priorState (red-team H3) so a filtered/rewound single feed contradicts what a
  // persistent watchtower already stored (a stateless per-call audit can be defeated by feed control).
  const ps = opts.priorState || {};
  const rootByEpoch = new Map(Object.entries(ps.rootByEpoch || {}).map(([e, r]) => [Number(e), r]));
  const kidPubkey = new Map(Object.entries(ps.kidPubkey || {}));   // kid → committed public_key_b64 (C2)
  const govKeys = new Set(ps.govKeys || []);                        // governance keys ever seen
  let maxEpoch = ps.maxEpoch != null ? Number(ps.maxEpoch) : -Infinity;
  let prevAt = ps.lastAt != null ? Number(ps.lastAt) : null;

  // H3: a single-feed audit with NO pinned governance key is low-assurance — the pin is the only defense
  // against a takeover whose history starts after the fact. Flag it (raise to a real posture requirement).
  if (!opts.governanceKey && !ps.govKeys) alerts.push(A('HIGH', 'unpinned-governance', 'no pinned governanceKey supplied — cannot prove the signer is the real operator from a single feed; pin it (ideally from the on-chain anchor) and persist state'));

  if ((!Array.isArray(observations) || observations.length === 0)) {
    const ok0 = alerts.filter((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH').length === 0;
    return { alerts: [...alerts, A('MEDIUM', 'no-observations', 'no observations to audit')], ok: false, seenEpochs: rootByEpoch.size, keysEverSeen: kidPubkey.size, state: exportState(rootByEpoch, kidPubkey, govKeys, maxEpoch, prevAt) };
  }

  for (let i = 0; i < observations.length; i++) {
    const o = observations[i];
    const dir = o.directory;
    const where = `obs[${i}] epoch=${dir && dir.epoch}`;

    // 1) Integrity: signature + root + kid-binding (verifyDirectory). Use signatureValid to tell a bad
    //    signature/root/kid (CRITICAL) apart from a merely-unpinned signer (handled by unpinned-governance).
    const v = verifyDirectory(dir, { governanceKey: opts.governanceKey });
    if (v.signatureValid !== true) { alerts.push(A('CRITICAL', 'bad-directory', `${where}: ${v.reason}`)); continue; }
    if (opts.governanceKey && dir.directory_public_key !== opts.governanceKey) {
      alerts.push(A('HIGH', 'untrusted-signer', `${where}: signed by a key != pinned governance key`)); // signature valid but wrong signer
    }

    // 2) Governance key change (takeover / compromise) — across the whole observed history.
    govKeys.add(dir.directory_public_key);
    if (govKeys.size > 1) alerts.push(A('HIGH', 'governance-key-change', `${where}: a NEW governance key ${dir.directory_public_key.slice(0, 16)}… signed the directory (rotation must be pre-announced + anchored)`));

    // 3) Equivocation: same epoch, different root.
    if (rootByEpoch.has(dir.epoch) && rootByEpoch.get(dir.epoch) !== dir.root) {
      alerts.push(A('CRITICAL', 'equivocation', `${where}: epoch ${dir.epoch} seen with TWO different roots — split view`));
    }
    rootByEpoch.set(dir.epoch, dir.root);

    // 4) Epoch rollback.
    if (dir.epoch < maxEpoch) alerts.push(A('HIGH', 'epoch-rollback', `${where}: epoch ${dir.epoch} < max seen ${maxEpoch} — rewind/rollback`));

    // 5) Chain continuity. On a normal +1 step, prev_root must chain. On a GAP (>maxEpoch+1) the
    //    continuity is UNVERIFIABLE — a hidden intermediate epoch could equivocate (red-team H2).
    if (maxEpoch > -Infinity) {
      if (dir.epoch === maxEpoch + 1 && rootByEpoch.has(maxEpoch)) {
        if ((dir.prev_root || '0'.repeat(64)) !== rootByEpoch.get(maxEpoch)) {
          alerts.push(A('HIGH', 'chain-break', `${where}: prev_root does not chain to epoch ${maxEpoch}'s root — discontinuity`));
        }
      } else if (dir.epoch > maxEpoch + 1) {
        alerts.push(A('HIGH', 'missing-epochs', `${where}: jumped from epoch ${maxEpoch} to ${dir.epoch} — intervening epochs never observed, continuity UNVERIFIABLE (supply them)`));
      }
    }
    if (dir.epoch > maxEpoch) maxEpoch = dir.epoch;

    // 6) C2: kid→pubkey binding. A kid must NEVER re-bind to a different public key (silent key
    //    substitution — the exact threat KT exists to stop), and a previously-committed kid must not vanish.
    const seenNow = new Set();
    for (const k of (dir.keys || [])) {
      seenNow.add(k.kid);
      if (kidPubkey.has(k.kid) && kidPubkey.get(k.kid) !== k.public_key_b64) {
        alerts.push(A('CRITICAL', 'key-rebind', `${where}: kid ${k.kid} re-bound to a DIFFERENT public key — silent key substitution`));
      }
      kidPubkey.set(k.kid, k.public_key_b64);
    }
    for (const kid of kidPubkey.keys()) if (!seenNow.has(kid)) alerts.push(A('HIGH', 'key-removed', `${where}: kid ${kid} was committed earlier but is GONE — append-only violated`));

    // 7) Anchor divergence (CRITICAL) / anchor missing (HIGH under requireAnchored — the anchor check is
    //    the strongest defense; its absence must not be a soft MEDIUM). NOTE: `anchoredRoot` MUST be read
    //    by the caller from an INDEPENDENT chain RPC/light-client — never from the same feed as `directory`.
    if (o.anchoredRoot != null && o.anchoredRoot !== '') {
      if (String(o.anchoredRoot).toLowerCase() !== String(dir.root).toLowerCase()) {
        alerts.push(A('CRITICAL', 'anchor-divergence', `${where}: directory root != on-chain anchoredRoot — the served directory is NOT the anchored one`));
      }
    } else if (opts.requireAnchored) {
      alerts.push(A('HIGH', 'anchor-missing', `${where}: no independently-read on-chain anchoredRoot — cannot confirm this is the anchored directory (do NOT treat as pass)`));
    }

    // 8) Liveness.
    if (prevAt != null && opts.maxObservationGap && (o.at - prevAt) > opts.maxObservationGap) {
      alerts.push(A('MEDIUM', 'operator-silent', `${where}: ${o.at - prevAt}s since previous observation exceeds maxObservationGap ${opts.maxObservationGap}s`));
    }
    prevAt = o.at;
  }

  const ok = alerts.filter((a) => a.severity === 'CRITICAL' || a.severity === 'HIGH').length === 0;
  return { alerts, ok, seenEpochs: rootByEpoch.size, keysEverSeen: kidPubkey.size, state: exportState(rootByEpoch, kidPubkey, govKeys, maxEpoch, prevAt) };
}

/** Serialize watchtower state so the next run can carry it forward (H3: persistence beats feed control). */
function exportState(rootByEpoch, kidPubkey, govKeys, maxEpoch, lastAt) {
  return {
    rootByEpoch: Object.fromEntries(rootByEpoch),
    kidPubkey: Object.fromEntries(kidPubkey),
    govKeys: [...govKeys],
    maxEpoch: maxEpoch === -Infinity ? null : maxEpoch,
    lastAt,
  };
}
