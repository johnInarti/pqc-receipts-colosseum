/**
 * mcp.tool-result/1 end-to-end over the OFFICIAL MCP TypeScript SDK (@modelcontextprotocol/sdk): a real Server and
 * Client connected by the SDK's InMemoryTransport. The server signs its CallToolResult; the client verifies what it
 * received. Nothing in MCP is changed: the receipt rides in `_meta["co.net.fractalai/receipt"]`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { signToolResult, verifyToolResult, MCP_META_KEY, X402_PAYMENT_RESPONSE_META } from '../src/mcp.ts';
import type { ToolResult } from '../src/mcp.ts';
import { testTrust } from '../src/testing.ts';

const T = testTrust();
// Shape of the de-facto x402 MCP transport (coinbase/x402 specs/transports-v2/mcp.md); values are test data.
const PAYMENT_RESPONSE = { success: true, transaction: '0x' + 'ab'.repeat(32), network: 'eip155:8453', payer: '0x' + '11'.repeat(20) };

async function connect(tamper?: (r: ToolResult) => ToolResult) {
  const server = new Server({ name: 'fractalai-paid-tools', version: '0.1.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'fx_quote', description: 'COP/USD quote', inputSchema: { type: 'object', properties: { pair: { type: 'string' } } } }] }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = req.params.arguments ?? {};
    const result: ToolResult = {
      content: [{ type: 'text', text: `quote for ${String(args.pair)}: 4012.55` }],
      structuredContent: { pair: args.pair, bid: '4012.50', ask: '4012.60', source: 'test' },
      _meta: { [X402_PAYMENT_RESPONSE_META]: PAYMENT_RESPONSE },
    };
    const signed = await signToolResult({ toolName: req.params.name, arguments: args, result }, T.issuer.signer);
    return (tamper ? tamper(signed) : signed) as never;
  });
  const client = new Client({ name: 'buyer-agent', version: '0.1.0' });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(st), client.connect(ct)]);
  return client;
}

test('official MCP SDK: signed tool result is accepted by the client (kernel + profile)', async () => {
  const client = await connect();
  const args = { pair: 'USD/COP' };
  const result = (await client.callTool({ name: 'fx_quote', arguments: args })) as ToolResult;
  assert.ok(result._meta?.[MCP_META_KEY], 'receipt survived the SDK round-trip in _meta');
  const d = await verifyToolResult({ toolName: 'fx_quote', arguments: args, result }, T.opts);
  assert.equal(d.verdict.valid, true, JSON.stringify(d.verdict.reasons));
  assert.equal(d.accepted, true, JSON.stringify(d.profile));
  const body = d.verdict.signed as Record<string, any>;
  assert.equal(body.payment.x402_transaction, PAYMENT_RESPONSE.transaction);
  assert.ok(d.profile!.checked.includes('payment_response_sha256'));
  await client.close();
});

test('structuredContent altered in transit (server bug / proxy) → refused', async () => {
  const client = await connect((r) => ({ ...r, structuredContent: { ...(r.structuredContent as object), bid: '3000.00' } }));
  const args = { pair: 'USD/COP' };
  const result = (await client.callTool({ name: 'fx_quote', arguments: args })) as ToolResult;
  const d = await verifyToolResult({ toolName: 'fx_quote', arguments: args, result }, T.opts);
  assert.equal(d.verdict.valid, true);
  assert.equal(d.accepted, false);
  assert.match(d.profile!.failures.join(';'), /content\/structuredContent differ/);
  await client.close();
});

test('x402 payment-response swapped after signing → refused', async () => {
  const client = await connect((r) => ({ ...r, _meta: { ...r._meta, [X402_PAYMENT_RESPONSE_META]: { ...PAYMENT_RESPONSE, transaction: '0x' + 'cd'.repeat(32) } } }));
  const args = { pair: 'USD/COP' };
  const result = (await client.callTool({ name: 'fx_quote', arguments: args })) as ToolResult;
  const d = await verifyToolResult({ toolName: 'fx_quote', arguments: args, result }, T.opts);
  assert.equal(d.accepted, false);
  assert.match(d.profile!.failures.join(';'), /payment-response/);
  await client.close();
});

test('receipt replayed for other arguments → refused', async () => {
  const client = await connect();
  const result = (await client.callTool({ name: 'fx_quote', arguments: { pair: 'USD/COP' } })) as ToolResult;
  const d = await verifyToolResult({ toolName: 'fx_quote', arguments: { pair: 'USD/BRL' }, result }, T.opts);
  assert.equal(d.accepted, false);
  assert.match(d.profile!.failures.join(';'), /other arguments/);
  await client.close();
});

test('missing receipt → not accepted', async () => {
  const client = await connect((r) => { const { [MCP_META_KEY]: _x, ...rest } = r._meta ?? {}; return { ...r, _meta: rest }; });
  const result = (await client.callTool({ name: 'fx_quote', arguments: { pair: 'USD/COP' } })) as ToolResult;
  const d = await verifyToolResult({ toolName: 'fx_quote', arguments: { pair: 'USD/COP' }, result }, T.opts);
  assert.equal(d.accepted, false);
  await client.close();
});
