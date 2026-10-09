/**
 * erc8004.validation/1 end-to-end on a local anvil chain against the OFFICIAL ERC-8004 Identity + Validation
 * registries (erc-8004/erc-8004-contracts @ b9e466c2, unmodified, compiled with the repo's settings).
 * Roles: account 1 = agent owner, account 2 = FractalAI validator (an EOA here; FractalProofOfDecisionValidator8004
 * in smart-contracts/ is the contract variant), account 0 = deployer.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { foundry } from 'viem/chains';
import type { Address, Hex } from 'viem';
import { receiptBytes, utf8 } from '../src/core.ts';
import {
  VALIDATION_REGISTRY_ABI, REQUEST_SCHEMA, requestPayloadBytes, keccakOf, issueValidationReceipt, buildValidationBody,
  responseArgs, verifyValidation, ERC8004_TAG,
} from '../src/erc8004.ts';
import type { ValidationRequestPayload, ValidationContext } from '../src/erc8004.ts';
import { testTrust } from '../src/testing.ts';
import { startChain, registerAgent, dataUri, fromDataUri } from './erc8004-helpers.ts';
import type { Chain } from './erc8004-helpers.ts';

const T = testTrust();
let C: Chain;
before(async () => { C = await startChain(18545 + Math.floor(Math.random() * 1000)); });
after(() => C?.stop());

const OUTPUT = utf8(JSON.stringify({ task: 'summarise filing 10-Q', summary: 'Revenue +12% QoQ; no going-concern note.' }));

async function requestFlow(outputForPayload = OUTPUT) {
  const [, agentW, validatorW] = C.wallets;
  const agentId = await registerAgent(C, agentW, 'https://agent.example/card.json');
  const payload: ValidationRequestPayload = {
    schema: REQUEST_SCHEMA, chain: `eip155:${foundry.id}`, identity_registry: C.identity.toLowerCase(), agent_id: agentId.toString(),
    validator: validatorW.account!.address.toLowerCase(),
    output: { sha256: (await import('../src/core.ts')).sha256Of(outputForPayload), media_type: 'application/json' },
    payment: { scheme: 'x402-exact', network: 'eip155:8453', tx_hash: '0x' + '5a'.repeat(32), amount_atomic: '20000', asset: 'USDC' },
  };
  const reqBytes = requestPayloadBytes(payload);
  const requestHash = keccakOf(reqBytes);
  const hash = await agentW.writeContract({ address: C.validation, abi: VALIDATION_REGISTRY_ABI, functionName: 'validationRequest', args: [validatorW.account!.address, agentId, dataUri(reqBytes), requestHash], account: agentW.account!, chain: foundry });
  await C.pub.waitForTransactionReceipt({ hash });
  const ctx: ValidationContext = { chainId: foundry.id, validationRegistry: C.validation, identityRegistry: C.identity, agentId, requestHash, validator: validatorW.account!.address };
  return { agentId, requestHash, reqUri: dataUri(reqBytes), ctx };
}

async function respond(requestHash: Hex, bytes: Uint8Array, receipt: Parameters<typeof responseArgs>[1], w = C.wallets[2]) {
  const args = responseArgs(requestHash, receipt, dataUri(bytes));
  const hash = await w.writeContract({ address: C.validation, abi: VALIDATION_REGISTRY_ABI, functionName: 'validationResponse', args, account: w.account!, chain: foundry });
  return C.pub.waitForTransactionReceipt({ hash });
}

test('validator flow on the official registries: request → PQC receipt → validationResponse → third-party verification', async () => {
  const { requestHash, reqUri, ctx } = await requestFlow();
  // validator fetches the request payload from requestURI and checks it before signing
  const receipt = await issueValidationReceipt(ctx, fromDataUri(reqUri), OUTPUT, T.issuer.signer);
  const served = receiptBytes(receipt);
  const rc = await respond(requestHash, served, receipt);
  assert.equal(rc.status, 'success');
  const st = await C.pub.readContract({ address: C.validation, abi: VALIDATION_REGISTRY_ABI, functionName: 'getValidationStatus', args: [requestHash] });
  assert.equal(st[2], 100);
  assert.equal(st[4], ERC8004_TAG);
  // third party: chain state + bytes served at responseURI
  const d = await verifyValidation(C.pub, C.validation, requestHash, served, T.opts, OUTPUT);
  assert.equal(d.verdict.valid, true, JSON.stringify(d.verdict.reasons));
  assert.equal(d.accepted, true, JSON.stringify(d.profile));
  assert.equal((d.verdict.signed as any).payment.tx_hash, '0x' + '5a'.repeat(32));
});

test('substituted receipt (another genuine receipt served at responseURI) → responseHash mismatch', async () => {
  const a = await requestFlow();
  const ra = await issueValidationReceipt(a.ctx, fromDataUri(a.reqUri), OUTPUT, T.issuer.signer);
  await respond(a.requestHash, receiptBytes(ra), ra);
  const b = await requestFlow();
  const rb = await issueValidationReceipt(b.ctx, fromDataUri(b.reqUri), OUTPUT, T.issuer.signer);
  await respond(b.requestHash, receiptBytes(rb), rb);
  const d = await verifyValidation(C.pub, C.validation, a.requestHash, receiptBytes(rb), T.opts, OUTPUT);
  assert.equal(d.verdict.valid, true);
  assert.equal(d.accepted, false);
  const f = d.profile!.failures.join(';');
  assert.match(f, /responseHash/);
  assert.match(f, /another request/);
});

test('only the validator named in the request can respond (official contract enforces it)', async () => {
  const { requestHash, reqUri, ctx } = await requestFlow();
  const r = await issueValidationReceipt(ctx, fromDataUri(reqUri), OUTPUT, T.issuer.signer);
  await assert.rejects(respond(requestHash, receiptBytes(r), r, C.wallets[1]), /not validator|reverted/);
});

test('validator refuses: payload altered after the request, output that does not match', async () => {
  const { reqUri, ctx } = await requestFlow();
  const bytes = fromDataUri(reqUri);
  const altered = utf8(new TextDecoder().decode(bytes).replace('"amount_atomic":"20000"', '"amount_atomic":"2000000"'));
  assert.throws(() => buildValidationBody(ctx, altered, OUTPUT), /keccak256\(request payload\) != requestHash/);
  assert.throws(() => buildValidationBody(ctx, bytes, utf8('another output')), /delivered output does not match/);
  assert.throws(() => buildValidationBody({ ...ctx, validator: C.wallets[1].account!.address as Address }, bytes, OUTPUT), /another validator/);
});

test('relying party with the wrong output bytes → refused; with no profile output → still accepted on chain facts', async () => {
  const { requestHash, reqUri, ctx } = await requestFlow();
  const r = await issueValidationReceipt(ctx, fromDataUri(reqUri), OUTPUT, T.issuer.signer);
  await respond(requestHash, receiptBytes(r), r);
  const bad = await verifyValidation(C.pub, C.validation, requestHash, receiptBytes(r), T.opts, utf8('tampered'));
  assert.equal(bad.accepted, false);
  const noOut = await verifyValidation(C.pub, C.validation, requestHash, receiptBytes(r), T.opts);
  assert.equal(noOut.accepted, true);
});
