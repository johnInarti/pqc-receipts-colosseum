/**
 * Profile `mcp.tool-result/1` — a post-quantum receipt carried inside an MCP `CallToolResult`
 * (Model Context Protocol, spec revision 2026-07-28).
 *
 * MCP results are unattested: `content` / `structuredContent` reach the client with no signature, and the de-facto
 * x402 transport puts the settlement in `_meta["x402/payment-response"]`, also unsigned. This profile signs:
 *   bindings.tool_name, bindings.arguments_sha256 = sha256(JCS(arguments))
 *   bindings.payment_response_sha256 = sha256(JCS(_meta["x402/payment-response"]))   (only if present)
 *   payment.*  = caller-supplied payment identifiers (or the x402 settlement fields, if present)
 *   delivery.sha256 = sha256(JCS({ content, structuredContent?, isError }))           (`_meta` excluded)
 * and travels in `_meta["co.net.fractalai/receipt"]` (reverse-DNS prefix of fractalai.net.co, as MCP requires
 * for `_meta` keys). Clients that do not know the key ignore it; nothing in MCP changes.
 */
import { jcs, sha256Of, makeBody, issueReceipt, verifyReceipt, profileCheck, decide, signedBody } from './core.ts';
import type { CommerceBody, CommerceReceipt, Signer, TrustOptions, ProfileCheck, Decision } from './core.ts';

export const MCP_META_KEY = 'co.net.fractalai/receipt';
export const MCP_PROTOCOL = 'mcp';
export const MCP_PROFILE = 'mcp.tool-result/1';
export const X402_PAYMENT_RESPONSE_META = 'x402/payment-response';

export interface ToolResult { content?: unknown[]; structuredContent?: unknown; isError?: boolean; _meta?: Record<string, unknown>; [k: string]: unknown }

export const resultDigestInput = (r: ToolResult): string =>
  jcs({ content: r.content ?? [], ...(r.structuredContent !== undefined ? { structuredContent: r.structuredContent } : {}), isError: r.isError === true });

function x402Payment(r: ToolResult): Record<string, string> {
  const pr = r._meta?.[X402_PAYMENT_RESPONSE_META] as Record<string, unknown> | undefined;
  if (!pr || typeof pr !== 'object') return {};
  const out: Record<string, string> = { scheme: 'x402' };
  for (const [k, dst] of [['transaction', 'x402_transaction'], ['network', 'x402_network'], ['payer', 'x402_payer']] as const) {
    if (typeof pr[k] === 'string' && pr[k]) out[dst] = pr[k] as string;
  }
  return out;
}

export interface McpCall { toolName: string; arguments?: unknown; result: ToolResult }

export function buildMcpBody(call: McpCall, extraPayment: Record<string, string> = {}, issuedAt?: number): CommerceBody {
  const pr = call.result._meta?.[X402_PAYMENT_RESPONSE_META];
  const bindings: Record<string, string> = { tool_name: call.toolName, arguments_sha256: sha256Of(jcs(call.arguments ?? {})) };
  if (pr !== undefined) bindings.payment_response_sha256 = sha256Of(jcs(pr));
  const payment = { ...x402Payment(call.result), ...extraPayment };
  if (Object.keys(payment).length === 0) payment.method = 'none';
  const input = resultDigestInput(call.result);
  return makeBody({ protocol: MCP_PROTOCOL, profile: MCP_PROFILE, issued_at: issuedAt, payment, bindings, delivery: { sha256: sha256Of(input), media_type: 'application/json', size: new TextEncoder().encode(input).length } });
}

/** Server side: sign the result and return it with the receipt in `_meta` (the signed digest excludes `_meta`). */
export async function signToolResult(call: McpCall, signer: Signer, extraPayment: Record<string, string> = {}, issuedAt?: number): Promise<ToolResult> {
  const receipt = await issueReceipt(buildMcpBody(call, extraPayment, issuedAt), signer);
  return { ...call.result, _meta: { ...(call.result._meta ?? {}), [MCP_META_KEY]: receipt } };
}

export function extractReceiptText(r: ToolResult): string | null {
  const x = r._meta?.[MCP_META_KEY];
  return x === undefined || x === null ? null : JSON.stringify(x);
}

export function checkMcp(body: CommerceBody, call: McpCall): ProfileCheck {
  const c = profileCheck(MCP_PROFILE);
  c.check(body.protocol === MCP_PROTOCOL && body.profile === MCP_PROFILE, 'profile', `profile is ${body.protocol}/${body.profile}`);
  c.check(body.bindings.tool_name === call.toolName, 'tool_name', `receipt is for tool ${body.bindings.tool_name}, not ${call.toolName}`);
  c.check(body.bindings.arguments_sha256 === sha256Of(jcs(call.arguments ?? {})), 'arguments_sha256', 'receipt was issued for other arguments');
  c.check(body.delivery.sha256 === sha256Of(resultDigestInput(call.result)), 'delivery.sha256', 'content/structuredContent differ from what was signed');
  const pr = call.result._meta?.[X402_PAYMENT_RESPONSE_META];
  if (pr !== undefined || body.bindings.payment_response_sha256 !== undefined) {
    c.check(pr !== undefined && body.bindings.payment_response_sha256 === sha256Of(jcs(pr)), 'payment_response_sha256', 'x402 payment-response in _meta differs from the signed one (or is missing)');
  }
  return c.result();
}

/** Client side: kernel verdict + profile check against the call it actually made and the result it received. */
export async function verifyToolResult(call: McpCall, trust: TrustOptions): Promise<Decision> {
  const text = extractReceiptText(call.result);
  if (text === null) return { accepted: false, verdict: await verifyReceipt('{}', trust), profile: null };
  const verdict = await verifyReceipt(text, trust);
  const body = signedBody(verdict);
  return decide(verdict, body ? checkMcp(body, call) : null);
}
export type { CommerceReceipt };
