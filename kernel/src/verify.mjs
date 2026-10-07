/**
 * The decision algorithm (spec/TRUST-KERNEL.md §9) — the ONLY place in this repository that decides
 * whether a FractalAI receipt is trusted. Every other module (verifier/, conformance/, the GitHub Action,
 * the Python port) either delegates here or reproduces this algorithm against the shared corpus.
 *
 * Never throws: every failure becomes a coded reason in a leveled verdict.
 */
import { C, KernelError, KERNEL_ID, SPEC_VERSION, LEVELS, DEFAULT_REQUIRE, EXIT } from './codes.mjs';
import { parseJsonStrict, assertJsonValue, isPlainObject, own } from './hygiene.mjs';
import { mldsaVerify, kidForKey } from './crypto.mjs';
import { KINDS, KIND_NAMES } from './domains.mjs';
import { parseReceipt, inferKind, anchorIds } from './kinds.mjs';
import { verifyDirectoryChain } from './directory.mjs';
import { keyAuthorizes } from './lifecycle.mjs';
import { verifyEvmAnchor } from './anchors/evm.mjs';
import { verifySolanaAnchor } from './anchors/solana.mjs';
import { SELF_TEST } from './selftest.mjs';
import { BAKED_ROOTS, BAKED_CHECKPOINT_DIRECTORY } from './roots.mjs';

const nowSec = () => Math.floor(Date.now() / 1000);
/** Defensive deep copy through the kernel's own strict parser (no shared references, no prototypes). */
const freeze = (v) => parseJsonStrict(JSON.stringify(v));

function toValue(x, what, allowObject) {
  if (typeof x === 'string' || x instanceof Uint8Array) return parseJsonStrict(x);
  if (!allowObject) throw new KernelError(C.ENGINE_UNSAFE_OBJECT_INPUT, `${what}: this engine failed the native JSON key-cache self-test; pass raw JSON text (or set allowObjectInput, reflected as an override)`);
  assertJsonValue(x);
  return freeze(x);
}

function normalizePolicy(p = {}) {
  const require = Array.isArray(p.require) ? [...p.require] : [...DEFAULT_REQUIRE];
  for (const l of require) if (!LEVELS.includes(l)) throw new KernelError(C.INPUT_SHAPE, `unknown level ${l} in policy.require`);
  if (!require.includes('integrity')) require.unshift('integrity');
  return {
    require,
    allowTestnetAnchors: p.allowTestnetAnchors === true,
    requireKnownAnchorer: p.requireKnownAnchorer === true,
    minConfirmations: Number.isSafeInteger(p.minConfirmations) && p.minConfirmations >= 0 ? p.minConfirmations : 1,
    rpcQuorum: Number.isSafeInteger(p.rpcQuorum) && p.rpcQuorum >= 1 ? p.rpcQuorum : 1,
    skew: Number.isSafeInteger(p.maxClockSkewSec) && p.maxClockSkewSec >= 0 ? p.maxClockSkewSec : 900,
  };
}

/**
 * @param {string|Uint8Array|object} input   the receipt (raw JSON text preferred)
 * @param {object} opts
 *   kind | kinds        REQUIRED policy: the receipt kind(s) the caller expects (never taken from the document)
 *   expectedId          content id the caller asked for (64 hex): binds a fetched receipt to the request
 *   directory           key directory (text or object); directoryHistory: intermediate epochs
 *   trustedKeys         OVERRIDE: pinned base64 key set instead of the directory
 *   governanceKey, roots, allowTlsDirectory   OVERRIDES of the baked trust roots
 *   anchors             anchor references (default: receipt.anchors | receipt.anchor); checkAnchors: evaluate them
 *   rpc                 { 'eip155:42161': [urls], 'solana:devnet': [urls] }; solanaSigners (override)
 *   policy              { require, allowTestnetAnchors, requireKnownAnchorer, minConfirmations, rpcQuorum, maxClockSkewSec }
 *   now, fetchImpl, timeoutMs, allowObjectInput
 */
export async function verify(input, opts = {}) {
  const v = {
    kernel: KERNEL_ID, spec_version: SPEC_VERSION, kind: null, valid: false,
    levels: { integrity: false, authentic: false, trusted: false, time_anchored: null, finalized: null },
    trust_basis: 'none', policy: null, key: null, directory: null, signed: null, signed_time: null,
    anchors: [], overrides: [], ignored_unsigned_fields: [], reasons: [], exit_code: EXIT.integrity,
    engine: { self_test_ok: SELF_TEST.ok, native_json_key_cache_ok: SELF_TEST.native_json_key_cache_ok },
  };
  const reason = (level, e) => {
    const code = e instanceof KernelError ? e.code : C.INTERNAL;
    const detail = e instanceof KernelError ? e.detail : String(e?.message ?? e);
    v.reasons.push({ level, code, detail });
  };
  const finish = () => {
    v.valid = v.policy ? v.policy.require.every((l) => v.levels[l] === true) : false;
    const firstFail = (v.policy?.require ?? DEFAULT_REQUIRE).find((l) => v.levels[l] !== true);
    v.exit_code = v.valid ? EXIT.VALID : EXIT[firstFail ?? 'integrity'];
    return v;
  };
  try {
    if (!SELF_TEST.ok) { reason('integrity', new KernelError(C.ENGINE_SELFTEST_FAILED, `kernel self-test failed: ${JSON.stringify(SELF_TEST)}`)); return finish(); }
    const policy = normalizePolicy(opts.policy);
    v.policy = policy;
    const now = Number.isSafeInteger(opts.now) ? opts.now : nowSec();
    const allowObject = SELF_TEST.native_json_key_cache_ok || opts.allowObjectInput === true;
    if (opts.allowObjectInput === true && !SELF_TEST.native_json_key_cache_ok) v.overrides.push('allowObjectInput (engine JSON key-cache self-test failed)');

    // ── 1. integrity ────────────────────────────────────────────────────────────────────────────
    let receipt, parsed;
    try {
      receipt = toValue(input, 'receipt', allowObject);
      if (!isPlainObject(receipt)) throw new KernelError(C.INPUT_SHAPE, 'receipt is not a JSON object');
      const allowed = opts.kind !== undefined ? [opts.kind] : Array.isArray(opts.kinds) ? opts.kinds : null;
      if (!allowed || allowed.length === 0) throw new KernelError(C.KIND_UNKNOWN, 'policy must name the expected kind(s) (opts.kind / opts.kinds) — the document never chooses');
      for (const k of allowed) if (!KIND_NAMES.includes(k)) throw new KernelError(C.KIND_UNKNOWN, `unknown kind ${JSON.stringify(k)}`);
      const kind = allowed.length === 1 ? allowed[0] : inferKind(receipt);
      if (!allowed.includes(kind)) throw new KernelError(C.KIND_NOT_ALLOWED, `receipt looks like ${kind}, policy allows ${allowed.join(', ')}`);
      v.kind = kind;
      parsed = parseReceipt(receipt, kind);
      if (opts.expectedId !== undefined && opts.expectedId !== parsed.content_id) throw new KernelError(C.EXPECTED_ID_MISMATCH, 'the receipt is not the one that was requested (content id differs)');
      v.levels.integrity = true;
      v.ignored_unsigned_fields = parsed.ignored;
      v.signed_time = parsed.signed_time;
    } catch (e) { reason('integrity', e); return finish(); }

    // ── 2. authentic ────────────────────────────────────────────────────────────────────────────
    if (!mldsaVerify(parsed.sig, new TextEncoder().encode(parsed.message), parsed.pk)) {
      reason('authentic', new KernelError(C.SIGNATURE_INVALID, `ML-DSA-65 signature does not verify over the reconstructed ${parsed.kind} message`));
      return finish();
    }
    v.levels.authentic = true;
    v.signed = parsed.signed;
    v.key = { kid: kidForKey(parsed.public_key_b64) };

    // ── 3. time proofs (before trust: a revoked key needs one) ──────────────────────────────────
    const wantAnchors = opts.checkAnchors === true || policy.require.includes('time_anchored') || policy.require.includes('finalized');
    let anchorTime = null;
    if (wantAnchors) {
      v.levels.time_anchored = false; v.levels.finalized = false;
      let refs;
      try {
        const raw = opts.anchors !== undefined ? toValue(opts.anchors, 'anchors', true) : own(receipt, 'anchors') ? receipt.anchors : own(receipt, 'anchor') ? [receipt.anchor] : [];
        refs = Array.isArray(raw) ? raw : [raw];
        if (refs.length === 0) throw new KernelError(C.NO_ANCHOR, 'no anchor reference supplied');
        if (refs.length > 8) throw new KernelError(C.ANCHOR_REF_MALFORMED, 'more than 8 anchor references');
      } catch (e) { reason('time_anchored', e); refs = []; }
      if (opts.solanaSigners) v.overrides.push('solanaSigners');
      const roots = opts.roots ?? BAKED_ROOTS;
      const ids = anchorIds(parsed);
      for (const ref of refs) {
        const rec = { ref: null, ok: false, counts: false, facts: null, reason: null };
        try {
          if (!isPlainObject(ref)) throw new KernelError(C.ANCHOR_REF_MALFORMED, 'anchor reference is not an object');
          const isSol = ref.chain === 'solana';
          rec.ref = isSol ? `solana:${ref.cluster}` : `eip155:${ref.chain_id}`;
          const ctx = { roots, ids, signedTime: parsed.signed_time, policy, fetchImpl: opts.fetchImpl, timeoutMs: opts.timeoutMs, rpcUrls: opts.rpc?.[rec.ref], solanaSigners: opts.solanaSigners };
          const f = isSol ? await verifySolanaAnchor(ref, ctx) : await verifyEvmAnchor(ref, ctx);
          rec.ok = true; rec.facts = f;
          if (f.network_class !== 'production' && !policy.allowTestnetAnchors) throw new KernelError(C.ANCHOR_TESTNET_NOT_ALLOWED, `${rec.ref} is a test network; policy.allowTestnetAnchors is false`);
          if (policy.requireKnownAnchorer && !f.anchorer_known) throw new KernelError(C.ANCHOR_ANCHORER_UNKNOWN, `anchored by ${f.anchored_by}, not a known FractalAI anchorer`);
          rec.counts = true;
        } catch (e) {
          const code = e instanceof KernelError ? e.code : C.INTERNAL;
          rec.reason = { code, detail: e instanceof KernelError ? e.detail : String(e?.message ?? e) };
          v.reasons.push({ level: 'time_anchored', code, detail: `${rec.ref ?? 'anchor'}: ${rec.reason.detail}` });
        }
        v.anchors.push(rec);
      }
      const counted = v.anchors.filter((a) => a.counts);
      if (counted.length) {
        v.levels.time_anchored = true;
        anchorTime = Math.min(...counted.map((a) => a.facts.time));
        v.levels.finalized = counted.some((a) => a.facts.finalized === true);
        if (!v.levels.finalized) v.reasons.push({ level: 'finalized', code: C.NOT_FINALIZED, detail: 'no counted anchor is in a finalized block yet' });
      }
    }

    // ── 4. trusted ──────────────────────────────────────────────────────────────────────────────
    try {
      const kindSpec = KINDS[parsed.kind];
      if (opts.trustedKeys !== undefined) {
        const set = toValue(opts.trustedKeys, 'trustedKeys', true);
        if (!Array.isArray(set) || set.length === 0 || set.some((k) => typeof k !== 'string')) throw new KernelError(C.NO_TRUST_SOURCE, 'trustedKeys must be a non-empty array of base64 keys');
        v.overrides.push('trustedKeys'); v.trust_basis = 'override';
        if (parsed.signed_time !== null && parsed.signed_time > now + policy.skew) throw new KernelError(C.SIGNED_TIME_IN_FUTURE, `signed time ${parsed.signed_time} is in the future`);
        if (!set.includes(parsed.public_key_b64)) throw new KernelError(C.KEY_NOT_IN_PINNED_SET, 'signing key is not in the pinned trustedKeys set');
        v.key.time_basis = parsed.signed_time === null ? 'verification-time' : 'signed';
        v.levels.trusted = true;
      } else {
        if (kindSpec.trust === 'pinned-set-only') throw new KernelError(C.SELF_ATTEST_NOT_TRUSTED, 'a self-attest seal is signed by the seller; only an explicit trustedKeys set can trust it');
        if (opts.directory === undefined) throw new KernelError(C.NO_TRUST_SOURCE, 'no key directory supplied');
        const roots = opts.roots ?? BAKED_ROOTS;
        if (opts.roots) v.overrides.push('roots');
        let governanceKeyB64 = roots.governance?.public_key_b64;
        let checkpoint = roots.directory_checkpoint ? { epoch: roots.directory_checkpoint.epoch, root: roots.directory_checkpoint.root, directory: roots === BAKED_ROOTS ? BAKED_CHECKPOINT_DIRECTORY : undefined } : null;
        if (opts.governanceKey !== undefined) { v.overrides.push('governanceKey'); governanceKeyB64 = opts.governanceKey; if (opts.governanceKey !== roots.governance?.public_key_b64) checkpoint = opts.checkpoint ?? null; }
        const unpinned = opts.allowTlsDirectory === true;
        if (unpinned) { v.overrides.push('allowTlsDirectory'); checkpoint = null; }
        const dir = toValue(opts.directory, 'directory', allowObject);
        const history = opts.directoryHistory !== undefined ? toValue(opts.directoryHistory, 'directoryHistory', allowObject) : [];
        const d = verifyDirectoryChain(dir, { governanceKeyB64, checkpoint, history, unpinnedSigner: unpinned });
        v.directory = { epoch: d.epoch, root: d.root, chain_epochs: d.chain_epochs, checkpoint_epoch: checkpoint?.epoch ?? null };
        v.trust_basis = unpinned ? 'tls' : (opts.roots || opts.governanceKey !== undefined) ? 'override' : 'pinned-root';
        const entry = d.keys.find((k) => k.public_key_b64 === parsed.public_key_b64);
        if (!entry) throw new KernelError(C.KEY_NOT_LISTED, `key ${v.key.kid} is not in directory epoch ${d.epoch}`);
        Object.assign(v.key, { use: entry.use, status: entry.status, not_before: entry.not_before ?? null, not_after: entry.not_after ?? null, revoked_at: entry.revoked_at ?? null });
        const a = keyAuthorizes(entry, { uses: kindSpec.uses, signedTime: parsed.signed_time, now, anchorTime, skew: policy.skew });
        v.key.evaluated_at = a.evaluated_at; v.key.time_basis = a.time_basis;
        if (!a.ok) throw new KernelError(a.code, a.detail);
        v.levels.trusted = true;
      }
    } catch (e) {
      reason('trusted', e);
    }
    return finish();
  } catch (e) {
    reason('integrity', e);
    return finish();
  }
}
