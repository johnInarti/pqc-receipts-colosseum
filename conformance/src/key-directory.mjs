/**
 * Key Transparency for PQC agent-receipt keys — issuer tooling (buildDirectory) + a compatibility
 * `verifyDirectory` that DELEGATES to Trust Kernel v2 (strict structure, kid binding, recomputed root,
 * governance ML-DSA-65 signature, signer pinning, lifecycle via keyAuthorizes).
 *
 *   root = sha256(JCS({ epoch, prev_root, governance_key, keys sorted by kid }))
 *   signature = ML-DSA-65(governance key, "FRACTALAI-key-directory-v1\n" + root)
 *
 * Fail-closed: a self-signed directory is not trust. Supply a pinned `governanceKey` (out of band) or an
 * on-chain `anchoredRoot`; with neither, the kernel's BAKED FractalAI roots are used.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  directoryRoot, checkEpoch, verifyDirectoryChain, keyAuthorizes, kidForKey, parseJsonStrict, utf8,
  KEY_DIR_DOMAIN, ZERO_ROOT, BAKED_ROOTS, USE,
} from '@fractalai/pqc-trust-kernel';

export { KEY_DIR_DOMAIN, kidForKey, directoryRoot };

/** Build a signed directory epoch. `seedHex` is the GOVERNANCE key seed (distinct from receipt keys). */
export function buildDirectory(keys, seedHex, { epoch = 1, prevRoot = ZERO_ROOT } = {}) {
  const h = seedHex.trim();
  if (h.length !== 64 || !/^[0-9a-fA-F]+$/.test(h)) throw new Error('governance seed must be 64 hex chars');
  const kp = ml_dsa65.keygen(Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16))));
  const governanceKeyB64 = Buffer.from(kp.publicKey).toString('base64');
  const root = directoryRoot(keys, prevRoot, epoch, governanceKeyB64);
  const signedMessage = `${KEY_DIR_DOMAIN}\n${root}`;
  const signature = Buffer.from(ml_dsa65.sign(utf8(signedMessage), kp.secretKey, { extraEntropy: false })).toString('base64');
  return { spec: KEY_DIR_DOMAIN, epoch, prev_root: prevRoot, root, keys, signed_message: signedMessage, signature, directory_public_key: governanceKeyB64 };
}

/**
 * @param opts { governanceKey?, anchoredRoot?, expectedPrevRoot?, at?: unix s (lifecycle evaluation time) }
 * @returns { valid, signatureValid, reason, trustedKeys } — trustedKeys = receipt keys authorized at `at`.
 */
export function verifyDirectory(dir, opts = {}) {
  const NO = (reason, signatureValid = false) => ({ valid: false, signatureValid, reason, trustedKeys: [] });
  let d;
  try { d = parseJsonStrict(JSON.stringify(dir)); } catch (e) { return NO(`not a JSON directory: ${e.detail ?? e.message}`); }
  try { checkEpoch(d, undefined); } catch (e) { return NO(`${e.code}: ${e.detail}`); }
  try {
    const pinned = opts.governanceKey ?? (opts.anchoredRoot ? undefined : BAKED_ROOTS.governance.public_key_b64);
    const baked = pinned === BAKED_ROOTS.governance.public_key_b64 && opts.governanceKey === undefined;
    const r = verifyDirectoryChain(d, {
      governanceKeyB64: pinned, unpinnedSigner: pinned === undefined,
      checkpoint: baked ? { epoch: BAKED_ROOTS.directory_checkpoint.epoch, root: BAKED_ROOTS.directory_checkpoint.root } : null,
    });
    if (opts.anchoredRoot && String(opts.anchoredRoot).toLowerCase() !== d.root) return NO('directory root != on-chain anchored root — possible equivocation, refuse', true);
    if (opts.expectedPrevRoot && (d.prev_root ?? ZERO_ROOT) !== String(opts.expectedPrevRoot).toLowerCase()) return NO('prev_root does not chain to the expected previous epoch — discontinuity', true);
    const at = Number.isSafeInteger(opts.at) ? opts.at : Math.floor(Date.now() / 1000);
    const trustedKeys = r.keys.filter((k) => keyAuthorizes(k, { uses: [USE.RECEIPT], signedTime: Number.isSafeInteger(opts.at) ? at : null, now: at, anchorTime: null, skew: 0 }).ok).map((k) => k.public_key_b64);
    const how = opts.governanceKey ? 'pinned governance key' : opts.anchoredRoot ? 'signer whose root matches the on-chain anchor' : 'BAKED FractalAI governance key + checkpoint';
    return { valid: true, signatureValid: true, reason: `authentic: ML-DSA-65-signed directory by a ${how}; root recomputes`, trustedKeys, allKeys: r.keys.map((k) => k.public_key_b64) };
  } catch (e) {
    return NO(`${e.code ?? 'ERROR'}: ${e.detail ?? e.message}`, true);
  }
}
