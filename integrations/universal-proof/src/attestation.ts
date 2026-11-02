/**
 * Optional reference from a delivery receipt to an EXTERNAL capability attestation (a2aproject/A2A discussion #2330).
 *
 * Two separate claims, two separate signers:
 *   - the external attestation (issued by a third party, BEFORE payment): "this agent's skills behave as its card
 *     declares". Its format and signature belong to its issuer; this package never verifies or endorses it.
 *   - the delivery receipt (ML-DSA-65, AFTER delivery): "this is what was delivered, bound to this payment".
 *
 * The receipt only COMMITS to which attestation the agent presented. The signed body is not extended (the kernel's
 * commerce shape is closed, spec §13.2): the commitment is one more binding,
 *   bindings.capability_attestation_sha256 = sha256(JCS(ref))
 * and the reference object travels next to the receipt (A2A: artifact.metadata[CAPABILITY_ATTESTATION_METADATA_KEY]).
 * Receipts without the binding are unchanged, so existing verifiers keep working.
 */
import { jcs, sha256Of, profileCheck } from './core.ts';
import type { CommerceBody, ProfileCheck } from './core.ts';

export const CAPABILITY_ATTESTATION_BINDING = 'capability_attestation_sha256';
export const CAPABILITY_ATTESTATION_REF_VERSION = '1';

export interface CapabilityAttestationRef {
  v: typeof CAPABILITY_ATTESTATION_REF_VERSION;
  /** sha256 of the exact attestation document bytes the issuer serves at `uri`. */
  digest: { alg: 'sha-256'; value: string };
  /** Who issued it, e.g. an https origin or a did:web identifier. */
  issuer: string;
  /** The issuer's identifier for the key that signed the attestation. */
  key_id: string;
  /** Where a buyer resolves the attestation document (https only). */
  uri: string;
  /** The signature algorithm of the ATTESTATION (the issuer's choice, e.g. "ml-dsa-65", "es256", "ed25519"). */
  algorithm: string;
  /** Unix seconds. */
  issued_at: number;
  /** Unix seconds; must be later than issued_at. */
  expires_at: number;
}

const HEX64 = /^[0-9a-f]{64}$/;
const TOKEN = /^[\x21-\x7e]{1,256}$/;
const ALG = /^[a-z0-9][a-z0-9-]{0,31}$/;
const KEYS = ['algorithm', 'digest', 'expires_at', 'issued_at', 'issuer', 'key_id', 'uri', 'v'];

/** Strict shape check; throws on anything else (unknown keys included, so the committed bytes are unambiguous). */
export function checkCapabilityAttestationRef(r: unknown): CapabilityAttestationRef {
  const bad = (m: string): never => { throw new Error(`capability_attestation: ${m}`); };
  if (typeof r !== 'object' || r === null || Array.isArray(r)) bad('not an object');
  const o = r as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== KEYS.length || keys.some((k, i) => k !== KEYS[i])) bad(`must have exactly the keys ${KEYS.join(', ')}`);
  if (o.v !== CAPABILITY_ATTESTATION_REF_VERSION) bad(`v is not ${CAPABILITY_ATTESTATION_REF_VERSION}`);
  const d = o.digest as Record<string, unknown> | null;
  if (typeof d !== 'object' || d === null || Object.keys(d).sort().join(',') !== 'alg,value') bad('digest must be {alg, value}');
  if (d!.alg !== 'sha-256' || typeof d!.value !== 'string' || !HEX64.test(d!.value)) bad('digest must be sha-256 with 64 lowercase hex');
  for (const k of ['issuer', 'key_id'] as const) if (typeof o[k] !== 'string' || !TOKEN.test(o[k] as string)) bad(`${k} must be 1..256 printable ASCII without spaces`);
  let u: URL | null = null;
  try { u = new URL(String(o.uri)); } catch { /* handled below */ }
  if (typeof o.uri !== 'string' || !TOKEN.test(o.uri) || !u || u.protocol !== 'https:') bad('uri must be an https URL');
  if (typeof o.algorithm !== 'string' || !ALG.test(o.algorithm)) bad('algorithm must match ^[a-z0-9][a-z0-9-]{0,31}$');
  for (const k of ['issued_at', 'expires_at'] as const) if (!Number.isSafeInteger(o[k]) || (o[k] as number) < 1) bad(`${k} must be a positive safe integer (unix seconds)`);
  if ((o.expires_at as number) <= (o.issued_at as number)) bad('expires_at must be later than issued_at');
  return o as unknown as CapabilityAttestationRef;
}

/** Build a reference to an attestation document the agent holds (digest computed over its exact bytes). */
export function capabilityAttestationRef(document: string | Uint8Array, meta: Omit<CapabilityAttestationRef, 'v' | 'digest'>): CapabilityAttestationRef {
  return checkCapabilityAttestationRef({ issuer: meta.issuer, key_id: meta.key_id, uri: meta.uri, algorithm: meta.algorithm, issued_at: meta.issued_at, expires_at: meta.expires_at,
    v: CAPABILITY_ATTESTATION_REF_VERSION, digest: { alg: 'sha-256', value: sha256Of(document) } });
}

/** The binding an issuer merges into `bindings` before signing the receipt. */
export function capabilityAttestationBinding(ref: CapabilityAttestationRef): Record<string, string> {
  return { [CAPABILITY_ATTESTATION_BINDING]: sha256Of(jcs(checkCapabilityAttestationRef(ref))) };
}

/**
 * Relying-party check, run on the SIGNED body (after the kernel verified the signature):
 *   - the reference matches the signed commitment (or both are absent: then nothing is claimed);
 *   - the attestation was valid when the receipt was issued (issued_at <= receipt.issued_at < expires_at);
 *   - if `document` is given (fetched from ref.uri), its bytes match ref.digest.
 * It does NOT verify the attestation's own signature or judge its content: that is the issuer's format and claim.
 */
export function checkCapabilityAttestation(body: CommerceBody, ref: unknown, opts: { document?: string | Uint8Array; now?: number } = {}): ProfileCheck {
  const p = profileCheck('capability-attestation/1');
  const committed = body.bindings?.[CAPABILITY_ATTESTATION_BINDING];
  if (committed === undefined) {
    p.check(ref === undefined || ref === null, 'capability_attestation_absent', 'a capability attestation is presented but the signed receipt does not commit to any');
    return p.result();
  }
  let r: CapabilityAttestationRef | null = null;
  try { r = checkCapabilityAttestationRef(ref); } catch (e) { p.check(false, 'capability_attestation_ref', (e as Error).message); return p.result(); }
  p.check(sha256Of(jcs(r)) === committed, CAPABILITY_ATTESTATION_BINDING, 'capability attestation reference differs from the one the receipt signed');
  p.check(r.issued_at <= body.issued_at && body.issued_at < r.expires_at, 'capability_attestation_valid_at_issuance', 'capability attestation was not valid when the receipt was issued');
  if (opts.now !== undefined) p.check(opts.now < r.expires_at, 'capability_attestation_not_expired', 'capability attestation has expired');
  if (opts.document !== undefined) p.check(sha256Of(opts.document) === r.digest.value, 'capability_attestation_document', 'attestation document bytes do not match the referenced digest');
  return p.result();
}
