/**
 * Key directory (FRACTALAI-key-directory-v1) verification with pinned trust roots, epoch chain and
 * anti-rollback (spec/TRUST-KERNEL.md §6).
 *
 *   root = sha256(JCS({ epoch, prev_root, governance_key, keys: keys sorted by kid }))
 *   signature = ML-DSA-65(governance key, "FRACTALAI-key-directory-v1\n" + root)
 *
 * A directory is ACCEPTED only if it is structurally strict, its root recomputes, its signature verifies,
 * its signer equals the pinned governance key, and its epoch is reachable from the pinned checkpoint:
 *   epoch <  checkpoint.epoch  → DIRECTORY_ROLLBACK
 *   epoch == checkpoint.epoch  → root MUST equal checkpoint.root (else DIRECTORY_EQUIVOCATION)
 *   epoch >  checkpoint.epoch  → every intermediate epoch must be supplied (history), each verified the
 *                                same way, prev_root-linked, and append-only (no kid removed, no key rebound,
 *                                monotone status, immutable not_before / revoked_at).
 */
import { C, KernelError, fail } from './codes.mjs';
import { jcs, utf8 } from './canon.mjs';
import { sha256hex, kidForKey, mldsaVerify, ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES } from './crypto.mjs';
import { b64decodeStrict, isHex, isPlainObject, own } from './hygiene.mjs';
import { KEY_DIR_DOMAIN, USE } from './domains.mjs';

export const ZERO_ROOT = '0'.repeat(64);
export const STATUSES = Object.freeze(['reserved', 'active', 'retiring', 'retired', 'revoked']);
const ALLOWED_TRANSITIONS = {
  reserved: ['reserved', 'active', 'revoked'],
  active: ['active', 'retiring', 'retired', 'revoked'],
  retiring: ['retiring', 'retired', 'revoked'],
  retired: ['retired', 'revoked'],
  revoked: ['revoked'],
};
const KEY_FIELDS_TYPED = ['not_before', 'not_after', 'revoked_at', 'added_at'];

export function directoryRoot(keys, prevRoot, epoch, governanceKeyB64) {
  const canonicalKeys = [...keys].sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
  return sha256hex(jcs({ epoch, prev_root: prevRoot || ZERO_ROOT, governance_key: governanceKeyB64 || null, keys: canonicalKeys }));
}

const D = (detail) => new KernelError(C.DIRECTORY_INVALID, detail);

/** Structural + cryptographic check of ONE epoch against ONE governance key. Throws KernelError. */
export function checkEpoch(dir, governanceKeyB64) {
  if (!isPlainObject(dir)) throw D('directory is not an object');
  if (dir.spec !== KEY_DIR_DOMAIN) throw D(`spec is not ${KEY_DIR_DOMAIN}`);
  if (!Number.isSafeInteger(dir.epoch) || dir.epoch < 1) throw D('epoch is not a positive integer');
  if (!isHex(dir.root, 64)) throw D('root is not 64 lowercase hex');
  if (own(dir, 'prev_root') && dir.prev_root !== null && !isHex(dir.prev_root, 64)) throw D('prev_root is not 64 lowercase hex');
  if (dir.epoch === 1 && (dir.prev_root ?? ZERO_ROOT) !== ZERO_ROOT) throw D('epoch 1 must have a zero prev_root');
  if (!Array.isArray(dir.keys) || dir.keys.length === 0 || dir.keys.length > 256) throw D('keys[] missing, empty or > 256');
  const asDir = (f) => { try { return f(); } catch (e) { throw D(e instanceof KernelError ? e.detail : String(e)); } };
  const pk = asDir(() => b64decodeStrict(dir.directory_public_key, ML_DSA_65_PK_BYTES, 'directory_public_key'));
  const sig = asDir(() => b64decodeStrict(dir.signature, ML_DSA_65_SIG_BYTES, 'directory signature'));
  const kids = new Set(), pks = new Set();
  for (const k of dir.keys) {
    if (!isPlainObject(k)) throw D('key entry is not an object');
    if (typeof k.public_key_b64 !== 'string') throw D('key entry without public_key_b64');
    asDir(() => b64decodeStrict(k.public_key_b64, ML_DSA_65_PK_BYTES, `key ${String(k.kid).slice(0, 16)} public_key_b64`));
    if (k.kid !== kidForKey(k.public_key_b64)) throw D(`kid ${String(k.kid).slice(0, 20)} != sha256(public_key_b64)[:16] (aliased kid)`);
    if (kids.has(k.kid) || pks.has(k.public_key_b64)) throw D(`key ${k.kid} listed more than once (ambiguous status)`);
    kids.add(k.kid); pks.add(k.public_key_b64);
    if (typeof k.use !== 'string') throw D(`key ${k.kid} has no use`);
    if (!STATUSES.includes(k.status)) throw D(`key ${k.kid} status ${JSON.stringify(k.status)} is not one of ${STATUSES.join('|')}`);
    for (const f of KEY_FIELDS_TYPED) {
      if (own(k, f) && k[f] !== null && !(Number.isSafeInteger(k[f]) && k[f] >= 0)) throw D(`key ${k.kid} ${f} must be a non-negative integer or null`);
    }
  }
  if (pks.has(dir.directory_public_key)) throw D('governance key is also listed as a receipt key (use separation violated)');
  const recomputed = directoryRoot(dir.keys, dir.prev_root, dir.epoch, dir.directory_public_key);
  if (recomputed !== dir.root) throw D('root does not recompute over {epoch, prev_root, governance_key, keys}');
  const message = `${KEY_DIR_DOMAIN}\n${dir.root}`;
  if (own(dir, 'signed_message') && dir.signed_message !== message) throw D('signed_message != "FRACTALAI-key-directory-v1\\n" + root');
  if (!mldsaVerify(sig, utf8(message), pk)) throw D('governance ML-DSA-65 signature does not verify');
  if (governanceKeyB64 !== undefined && dir.directory_public_key !== governanceKeyB64) {
    throw new KernelError(C.DIRECTORY_SIGNER_NOT_PINNED, 'directory is signed by a key that is not the pinned governance key');
  }
  return dir;
}

function checkAppendOnly(prev, next) {
  const nextBy = new Map(next.keys.map((k) => [k.kid, k]));
  for (const a of prev.keys) {
    const b = nextBy.get(a.kid);
    if (!b) fail(C.DIRECTORY_NOT_APPEND_ONLY, `epoch ${next.epoch} removed key ${a.kid}`);
    if (b.public_key_b64 !== a.public_key_b64 || b.use !== a.use) fail(C.DIRECTORY_NOT_APPEND_ONLY, `epoch ${next.epoch} rebound key ${a.kid}`);
    if (!ALLOWED_TRANSITIONS[a.status].includes(b.status)) fail(C.DIRECTORY_NOT_APPEND_ONLY, `key ${a.kid}: status ${a.status} → ${b.status} not allowed`);
    if (a.not_before != null && b.not_before !== a.not_before) fail(C.DIRECTORY_NOT_APPEND_ONLY, `key ${a.kid}: not_before changed`);
    if (a.revoked_at != null && b.revoked_at !== a.revoked_at) fail(C.DIRECTORY_NOT_APPEND_ONLY, `key ${a.kid}: revoked_at changed`);
    if (a.not_after != null && b.not_after != null && b.not_after > a.not_after) fail(C.DIRECTORY_NOT_APPEND_ONLY, `key ${a.kid}: not_after extended`);
  }
}

/**
 * Verify a directory against trust roots.
 * @param {object} dir           latest epoch
 * @param {object} ctx
 * @param {object} ctx.governanceKeyB64   pinned governance key (from roots or override)
 * @param {object} ctx.checkpoint         { epoch, root } pinned checkpoint, or null (override: no anti-rollback)
 * @param {object[]} [ctx.history]        intermediate epochs (checkpoint.epoch+1 … dir.epoch-1), any order
 * @param {boolean} [ctx.unpinnedSigner]  accept any signer (TLS trust); reported, never silent
 * @returns {{ epoch, root, keys, chain_epochs:number[], signer_pinned:boolean }}
 */
export function verifyDirectoryChain(dir, ctx) {
  const gk = ctx.unpinnedSigner ? undefined : ctx.governanceKeyB64;
  if (!ctx.unpinnedSigner && typeof gk !== 'string') fail(C.NO_TRUST_SOURCE, 'no pinned governance key');
  checkEpoch(dir, gk);
  const signer = dir.directory_public_key;
  const cp = ctx.checkpoint;
  if (!cp) return { epoch: dir.epoch, root: dir.root, keys: dir.keys, chain_epochs: [dir.epoch], signer_pinned: !ctx.unpinnedSigner };
  if (dir.epoch < cp.epoch) fail(C.DIRECTORY_ROLLBACK, `directory epoch ${dir.epoch} < pinned checkpoint epoch ${cp.epoch}`);
  if (dir.epoch === cp.epoch) {
    if (dir.root !== cp.root) fail(C.DIRECTORY_EQUIVOCATION, `epoch ${dir.epoch} root ${dir.root.slice(0, 12)}… != pinned checkpoint root ${cp.root.slice(0, 12)}…`);
    return { epoch: dir.epoch, root: dir.root, keys: dir.keys, chain_epochs: [dir.epoch], signer_pinned: !ctx.unpinnedSigner };
  }
  // epoch > checkpoint: rebuild the chain checkpoint → … → dir from supplied history.
  const byEpoch = new Map();
  for (const h of ctx.history || []) {
    if (!isPlainObject(h) || !Number.isSafeInteger(h.epoch)) fail(C.DIRECTORY_INVALID, 'history entry is not a directory');
    if (h.epoch <= cp.epoch || h.epoch >= dir.epoch) continue;
    if (byEpoch.has(h.epoch) && byEpoch.get(h.epoch).root !== h.root) fail(C.DIRECTORY_EQUIVOCATION, `two different roots supplied for epoch ${h.epoch}`);
    byEpoch.set(h.epoch, h);
  }
  let prevRoot = cp.root;
  // Full checkpoint body (baked with the roots, or supplied in history) enables append-only checks from the checkpoint.
  let prevDir = null;
  const cpBody = cp.directory ?? (ctx.history || []).find((h) => isPlainObject(h) && h.epoch === cp.epoch);
  if (cpBody) {
    checkEpoch(cpBody, gk);
    if (cpBody.root !== cp.root) fail(C.DIRECTORY_EQUIVOCATION, `supplied checkpoint epoch ${cp.epoch} body does not match the pinned root`);
    prevDir = cpBody;
  }
  const chain = [cp.epoch];
  for (let e = cp.epoch + 1; e <= dir.epoch; e++) {
    const cur = e === dir.epoch ? dir : byEpoch.get(e);
    if (!cur) fail(C.DIRECTORY_CHAIN_GAP, `epoch ${e} missing between pinned checkpoint ${cp.epoch} and ${dir.epoch} — continuity unverifiable`);
    if (cur !== dir) checkEpoch(cur, gk);
    if (cur.directory_public_key !== signer) fail(C.DIRECTORY_SIGNER_NOT_PINNED, `epoch ${e} signed by a different governance key`);
    if ((cur.prev_root ?? ZERO_ROOT) !== prevRoot) fail(C.DIRECTORY_CHAIN_BREAK, `epoch ${e} prev_root does not equal epoch ${e - 1} root`);
    if (prevDir) checkAppendOnly(prevDir, cur);
    prevRoot = cur.root; prevDir = cur; chain.push(e);
  }
  return { epoch: dir.epoch, root: dir.root, keys: dir.keys, chain_epochs: chain, signer_pinned: !ctx.unpinnedSigner };
}

/** Governance-key separation helper for callers that hold a key list without a directory. */
export const isReceiptUse = (k) => k && k.use === USE.RECEIPT;
