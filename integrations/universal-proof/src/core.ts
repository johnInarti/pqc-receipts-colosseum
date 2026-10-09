/**
 * agent-commerce-receipt (Trust Kernel spec 2.2 §13): issue and verify.
 *
 * A receipt binds `payment` identifiers + `bindings` (hashes of the protocol's own artifacts) + `delivery.sha256`
 * under one ML-DSA-65 signature. Verification is ALWAYS delegated to the Trust Kernel (never re-implemented here);
 * the adapters (ap2.ts, erc8004.ts, mcp.ts) then re-derive the profile-specific bindings from the artifacts.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  verify as kernelVerify, verifySync as kernelVerifySync, commerceSigningMessage, checkCommerceBody, jcs, sha256hex, b64encode,
  COMMERCE_DOMAIN, COMMERCE_VERSION,
} from '@fractalai/pqc-trust-kernel';
import type { Verdict, VerifyOptions } from '@fractalai/pqc-trust-kernel';

export { COMMERCE_DOMAIN, COMMERCE_VERSION, jcs, sha256hex };
export type { Verdict, VerifyOptions };
export const KIND = 'agent-commerce-receipt';

export interface Delivery { sha256: string; media_type?: string; size?: number }
export interface CommerceBody {
  v: string;
  protocol: string;
  profile: string;
  issued_at: number;
  payment: Record<string, string>;
  bindings: Record<string, string>;
  delivery: Delivery;
}
export interface CommerceReceipt {
  algorithm: 'ml-dsa-65';
  domain: string;
  commerce_id: string;
  signed_message: string;
  issued_at: number;
  public_key: string;
  signature: string;
  commerce: CommerceBody;
}

/** Anything that can produce an ML-DSA-65 signature over bytes (a local key, an HSM, a remote signer). */
export interface Signer { publicKeyB64: string; sign(message: Uint8Array): Uint8Array | Promise<Uint8Array> }

const enc = new TextEncoder();
export const utf8 = (s: string): Uint8Array => enc.encode(s);
export const sha256Of = (data: string | Uint8Array): string => sha256hex(typeof data === 'string' ? utf8(data) : data);

/** Local ML-DSA-65 signer (FIPS 204, hedged by default; `deterministic` only for reproducible test vectors). */
export function localSigner(secretKey: Uint8Array, publicKey: Uint8Array, { deterministic = false } = {}): Signer {
  return {
    publicKeyB64: b64encode(publicKey),
    sign: (m) => ml_dsa65.sign(m, secretKey, deterministic ? { extraEntropy: false } : {}),
  };
}

/** Build a body and check it against the kernel's closed shape (throws a coded KernelError on any deviation). */
export function makeBody(b: Omit<CommerceBody, 'v' | 'issued_at'> & { issued_at?: number }): CommerceBody {
  const body: CommerceBody = {
    v: COMMERCE_VERSION, protocol: b.protocol, profile: b.profile,
    issued_at: b.issued_at ?? Math.floor(Date.now() / 1000),
    payment: { ...b.payment }, bindings: { ...b.bindings }, delivery: { ...b.delivery },
  };
  checkCommerceBody(body);
  return body;
}

export async function issueReceipt(body: CommerceBody, signer: Signer): Promise<CommerceReceipt> {
  const { commerce_id, message } = commerceSigningMessage(body);
  const sig = await signer.sign(utf8(message));
  return {
    algorithm: 'ml-dsa-65', domain: COMMERCE_DOMAIN, commerce_id, signed_message: message, issued_at: body.issued_at,
    public_key: signer.publicKeyB64, signature: b64encode(sig), commerce: body,
  };
}

/** Canonical serialisation used whenever a receipt is hashed or published (ERC-8004 responseHash, A2A, MCP). */
export const receiptBytes = (r: CommerceReceipt): Uint8Array => utf8(jcs(r));

export type TrustOptions = Omit<VerifyOptions, 'kind' | 'kinds'>;

/**
 * Kernel verdict for an agent-commerce-receipt. The kind is fixed by policy (never by the document).
 * Pass raw JSON text when the receipt came from the network (spec §8.1: the kernel's strict parser).
 */
export async function verifyReceipt(input: string | Uint8Array | CommerceReceipt, opts: TrustOptions = {}): Promise<Verdict> {
  return kernelVerify(typeof input === 'object' && !(input instanceof Uint8Array) ? JSON.stringify(input) : input, { ...opts, kind: KIND });
}
export function verifyReceiptSync(input: string | Uint8Array | CommerceReceipt, opts: TrustOptions = {}): Verdict {
  return kernelVerifySync(typeof input === 'object' && !(input instanceof Uint8Array) ? JSON.stringify(input) : input, { ...opts, kind: KIND });
}

/** Result of a profile check: the bindings a relying party re-derived from the protocol artifacts. */
export interface ProfileCheck { ok: boolean; profile: string; checked: string[]; failures: string[] }

export function profileCheck(profile: string): { check: (cond: boolean, what: string, failure: string) => void; result: () => ProfileCheck } {
  const checked: string[] = [];
  const failures: string[] = [];
  return {
    check(cond, what, failure) { checked.push(what); if (!cond) failures.push(failure); },
    result: () => ({ ok: failures.length === 0 && checked.length > 0, profile, checked, failures }),
  };
}

/** A complete decision: kernel verdict AND profile check. `accepted` is true only if both pass. */
export interface Decision { accepted: boolean; verdict: Verdict; profile: ProfileCheck | null }
export const decide = (verdict: Verdict, profile: ProfileCheck | null): Decision => ({
  accepted: verdict.valid && profile !== null && profile.ok, verdict, profile,
});

/** The signed body from a verdict (only exposed by the kernel once the signature verified). */
export function signedBody(v: Verdict): CommerceBody | null {
  if (!v.levels.authentic || !v.signed) return null;
  const { commerce_id: _id, ...body } = v.signed as Record<string, unknown>;
  return body as unknown as CommerceBody;
}
