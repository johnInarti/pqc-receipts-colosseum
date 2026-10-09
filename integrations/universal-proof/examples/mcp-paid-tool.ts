/**
 * Runnable: an MCP server (official TypeScript SDK) whose paid tool signs every result; a client verifies it.
 *   node examples/mcp-paid-tool.ts
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { signToolResult, verifyToolResult, MCP_META_KEY } from '../src/mcp.ts';
import type { ToolResult } from '../src/mcp.ts';
import { testTrust } from '../src/testing.ts';

const T = testTrust();
const server = new Server({ name: 'paid-tools', version: '0.1.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'fx_quote', description: 'quote', inputSchema: { type: 'object' } }] }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = req.params.arguments ?? {};
  const result: ToolResult = { content: [{ type: 'text', text: 'USD/COP 4012.55' }], structuredContent: { pair: 'USD/COP', mid: '4012.55' } };
  // payment identifiers come from whatever rail charged the call (x402, Stripe, PIX…); here a placeholder order id
  return (await signToolResult({ toolName: req.params.name, arguments: args, result }, T.issuer.signer, { order_id: 'ord-0001' })) as never;
});
const client = new Client({ name: 'buyer', version: '0.1.0' });
const [ct, st] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(st), client.connect(ct)]);

const args = { pair: 'USD/COP' };
const result = (await client.callTool({ name: 'fx_quote', arguments: args })) as ToolResult;
const d = await verifyToolResult({ toolName: 'fx_quote', arguments: args, result }, T.opts);
console.log(JSON.stringify({ meta_key: MCP_META_KEY, accepted: d.accepted, levels: d.verdict.levels, profile: d.profile }, null, 2));
await client.close();
