/**
 * Profile `ap2.fulfillment/1` — a post-quantum fulfillment receipt for an AP2 v0.2 purchase.
 *
 * AP2 v0.2 (google-agentic-commerce/AP2, 2026-04-28) ALREADY returns two signed receipts: a Checkout Receipt
 * (merchant, ES256 JWT) and a Payment Receipt (merchant payment processor, ES256 JWT), each with `reference` =
 * base64url(sha256(closed mandate SD-JWT)). What AP2 does not bind is WHAT WAS DELIVERED. This profile
 * countersigns, with ML-DSA-65:
 *   payment.payment_id / psp_confirmation_id / network_confirmation_id / order_id   (copied from the receipts)
 *   bindings.payment_receipt_sha256 / payment_receipt_iss / payment_mandate_ref       (sha256 hex of the compact JWT)
 *   bindings.checkout_receipt_sha256 / checkout_receipt_iss / checkout_mandate_ref    (when a checkout receipt exists)
 *   delivery.sha256                                                                    (the delivered content)
 * The issuer MUST verify both ES256 receipts (and, when it holds them, the closed mandates) BEFORE countersigning;
 * a relying party re-derives every binding from the same artifacts (checkAp2Fulfillment).
 * It complements AP2's receipts; it never replaces them.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { JsonWebKey } from 'node:crypto';
import { makeBody, issueReceipt, verifyReceipt, profileCheck, decide, signedBody, sha256Of } from './core.ts';
import type { CommerceBody, CommerceReceipt, Signer, TrustOptions, ProfileCheck, Decision } from './core.ts';

export const AP2_PROTOCOL = 'ap2';
export const AP2_PROFILE = 'ap2.fulfillment/1';

export interface Ap2Flow {
  paymentReceiptJwt: string;
  paymentReceiptIssuerJwk: JsonWebKey;
  checkoutReceiptJwt?: string;
  checkoutReceiptIssuerJwk?: JsonWebKey;
  /** The closed mandates (leaf JWT of the dSD-JWT chain), when the party holds them. */
  closedPaymentMandate?: string;
  closedCheckoutMandate?: string;
}

/** AP2 `reference` / `sd_hash`: base64url (no padding) of sha256 over the ASCII compact form (spec "Hashes"). */
export const ap2Reference = (compact: string): string => createHash('sha256').update(Buffer.from(compact, 'ascii')).digest('base64url');

export function decodeJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('not a compact JWS');
  return { header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')), payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) };
}

/** Verify an ES256 compact JWS with a P-256 JWK (the algorithm AP2 v0.2 mandates) and return its payload. */
export function verifyEs256(jwt: string, jwk: JsonWebKey): Record<string, unknown> {
  const { header, payload } = decodeJwt(jwt);
  if (header.alg !== 'ES256') throw new Error(`alg ${String(header.alg)} is not ES256`);
  const [h, p, s] = jwt.split('.');
  const ok = cryptoVerify('sha256', Buffer.from(`${h}.${p}`, 'ascii'), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('ES256 signature does not verify');
  return payload;
}

const str = (v: unknown, what: string): string => {
  if (typeof v !== 'string' || v.length === 0) throw new Error(`${what} missing`);
  return v;
};

interface ReadReceipts { pr: Record<string, unknown>; cr: Record<string, unknown> | null }

/** Verify the AP2 receipts as AP2 defines them (signature, Success status, reference = hash of the closed mandate). */
function readAp2(flow: Ap2Flow): ReadReceipts {
  const pr = verifyEs256(flow.paymentReceiptJwt, flow.paymentReceiptIssuerJwk);
  if (pr.status !== 'Success') throw new Error(`payment receipt status is ${String(pr.status)}, not Success`);
  if (flow.closedPaymentMandate !== undefined && pr.reference !== ap2Reference(flow.closedPaymentMandate)) throw new Error('payment receipt reference != hash of the closed payment mandate');
  let cr: Record<string, unknown> | null = null;
  if (flow.checkoutReceiptJwt !== undefined) {
    if (!flow.checkoutReceiptIssuerJwk) throw new Error('checkout receipt given without its issuer key');
    cr = verifyEs256(flow.checkoutReceiptJwt, flow.checkoutReceiptIssuerJwk);
    if (cr.status !== 'Success') throw new Error(`checkout receipt status is ${String(cr.status)}, not Success`);
    if (flow.closedCheckoutMandate !== undefined && cr.reference !== ap2Reference(flow.closedCheckoutMandate)) throw new Error('checkout receipt reference != hash of the closed checkout mandate');
  }
  return { pr, cr };
}

export interface DeliveredContent { bytes: string | Uint8Array; mediaType?: string }
const deliveryOf = (d: DeliveredContent) => {
  const bytes = typeof d.bytes === 'string' ? new TextEncoder().encode(d.bytes) : d.bytes;
  return { sha256: sha256Of(bytes), ...(d.mediaType ? { media_type: d.mediaType } : {}), size: bytes.length };
};

/** Issuer side: verify the AP2 artifacts, then build the body to countersign. Throws if AP2 itself does not verify. */
export function buildAp2FulfillmentBody(flow: Ap2Flow, delivered: DeliveredContent, issuedAt?: number): CommerceBody {
  const { pr, cr } = readAp2(flow);
  const payment: Record<string, string> = {
    payment_id: str(pr.payment_id, 'payment_id'),
    psp_confirmation_id: str(pr.psp_confirmation_id, 'psp_confirmation_id'),
    network_confirmation_id: str(pr.network_confirmation_id, 'network_confirmation_id'),
  };
  const bindings: Record<string, string> = {
    payment_receipt_sha256: sha256Of(flow.paymentReceiptJwt),
    payment_receipt_iss: str(pr.iss, 'payment receipt iss'),
    payment_mandate_ref: str(pr.reference, 'payment receipt reference'),
  };
  if (cr) {
    payment.order_id = str(cr.order_id, 'order_id');
    bindings.checkout_receipt_sha256 = sha256Of(flow.checkoutReceiptJwt!);
    bindings.checkout_receipt_iss = str(cr.iss, 'checkout receipt iss');
    bindings.checkout_mandate_ref = str(cr.reference, 'checkout receipt reference');
  }
  return makeBody({ protocol: AP2_PROTOCOL, profile: AP2_PROFILE, issued_at: issuedAt, payment, bindings, delivery: deliveryOf(delivered) });
}

export async function issueAp2FulfillmentReceipt(flow: Ap2Flow, delivered: DeliveredContent, signer: Signer, issuedAt?: number): Promise<CommerceReceipt> {
  return issueReceipt(buildAp2FulfillmentBody(flow, delivered, issuedAt), signer);
}

/** Relying-party side: re-derive every binding of the SIGNED body from the AP2 artifacts it holds. */
export function checkAp2Fulfillment(body: CommerceBody, flow: Ap2Flow, delivered?: DeliveredContent): ProfileCheck {
  const c = profileCheck(AP2_PROFILE);
  c.check(body.protocol === AP2_PROTOCOL && body.profile === AP2_PROFILE, 'profile', `profile is ${body.protocol}/${body.profile}`);
  let rr: ReadReceipts | null = null;
  try { rr = readAp2(flow); c.check(true, 'ap2 receipts (ES256, Success, reference)', ''); } catch (e) { c.check(false, 'ap2 receipts (ES256, Success, reference)', `AP2 artifacts do not verify: ${(e as Error).message}`); }
  if (rr) {
    const { pr, cr } = rr;
    c.check(body.bindings.payment_receipt_sha256 === sha256Of(flow.paymentReceiptJwt), 'payment_receipt_sha256', 'signed payment_receipt_sha256 is not the hash of the presented Payment Receipt');
    c.check(body.bindings.payment_receipt_iss === pr.iss, 'payment_receipt_iss', 'signed payment_receipt_iss differs');
    c.check(body.bindings.payment_mandate_ref === pr.reference, 'payment_mandate_ref', 'signed payment_mandate_ref differs from the receipt reference');
    for (const k of ['payment_id', 'psp_confirmation_id', 'network_confirmation_id'] as const) c.check(body.payment[k] === pr[k], k, `signed ${k} differs from the Payment Receipt`);
    if (cr) {
      c.check(body.bindings.checkout_receipt_sha256 === sha256Of(flow.checkoutReceiptJwt!), 'checkout_receipt_sha256', 'signed checkout_receipt_sha256 is not the hash of the presented Checkout Receipt');
      c.check(body.bindings.checkout_receipt_iss === cr.iss, 'checkout_receipt_iss', 'signed checkout_receipt_iss differs');
      c.check(body.bindings.checkout_mandate_ref === cr.reference, 'checkout_mandate_ref', 'signed checkout_mandate_ref differs from the receipt reference');
      c.check(body.payment.order_id === cr.order_id, 'order_id', 'signed order_id differs from the Checkout Receipt');
    } else {
      c.check(body.bindings.checkout_receipt_sha256 === undefined, 'no checkout receipt', 'receipt binds a checkout receipt that was not presented');
    }
  }
  if (delivered) c.check(body.delivery.sha256 === deliveryOf(delivered).sha256, 'delivery.sha256', 'delivered content does not match the signed delivery.sha256');
  return c.result();
}

/** Kernel verdict (issuer key trust) + profile check (AP2 artifacts + delivered content). */
export async function verifyAp2Fulfillment(receipt: string | CommerceReceipt, flow: Ap2Flow, delivered: DeliveredContent | undefined, trust: TrustOptions): Promise<Decision> {
  const verdict = await verifyReceipt(receipt, trust);
  const body = signedBody(verdict);
  return decide(verdict, body ? checkAp2Fulfillment(body, flow, delivered) : null);
}
