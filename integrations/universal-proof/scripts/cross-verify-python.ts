/**
 * Interoperability check: receipts issued by the TypeScript adapters are verified by the PYTHON port of the Trust
 * Kernel (second implementation, spec 2.2). Writes a bundle and runs:
 *   python -c "from fractalai_pqc_verify.kernel import verify; ..."
 * Usage: node scripts/cross-verify-python.ts <python-with-fractalai_pqc_verify-installed-from-.kernel/python>
 */
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { issueAp2FulfillmentReceipt } from '../src/ap2.ts';
import { artifactPartsDigestInput } from '../src/a2a.ts';
import { buildMcpBody } from '../src/mcp.ts';
import { issueReceipt } from '../src/core.ts';
import { testTrust } from '../src/testing.ts';

const py = process.argv[2] ?? 'python3';
const T = testTrust();
const fx = JSON.parse(readFileSync(new URL('../fixtures/ap2/flow-v0.2.json', import.meta.url), 'utf8'));
const artifact = { artifactId: 'a', parts: [{ data: JSON.parse(fx.delivered.content) }] };
const ap2 = await issueAp2FulfillmentReceipt({ paymentReceiptJwt: fx.payment_receipt_jwt, paymentReceiptIssuerJwk: fx.keys.mpp, checkoutReceiptJwt: fx.checkout_receipt_jwt, checkoutReceiptIssuerJwk: fx.keys.merchant }, { bytes: artifactPartsDigestInput(artifact) }, T.issuer.signer);
const mcp = await issueReceipt(buildMcpBody({ toolName: 'fx_quote', arguments: { pair: 'USD/COP' }, result: { content: [{ type: 'text', text: 'x' }] } }), T.issuer.signer);
const dir = mkdtempSync(join(tmpdir(), 'xverify-'));
const bundle = join(dir, 'bundle.json');
writeFileSync(bundle, JSON.stringify({ receipts: [JSON.stringify(ap2), JSON.stringify(mcp)], directory: JSON.stringify(T.directory), roots: T.roots }));
const code = `
import json,sys
from fractalai_pqc_verify.kernel import verify
b=json.load(open(sys.argv[1]))
out=[verify(r, kind="agent-commerce-receipt", directory=b["directory"], roots=b["roots"]) for r in b["receipts"]]
print(json.dumps([{"valid":v["valid"],"levels":v["levels"],"spec":v["spec_version"],"reasons":[x["code"] for x in v["reasons"]]} for v in out]))
`;
const res = JSON.parse(execFileSync(py, ['-c', code, bundle], { encoding: 'utf8' }));
console.log(JSON.stringify(res));
if (!res.every((v: { valid: boolean }) => v.valid)) process.exit(1);
console.log(`python port verified ${res.length}/${res.length} TS-issued receipts`);
