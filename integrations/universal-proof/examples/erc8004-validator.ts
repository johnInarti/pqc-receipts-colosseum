/**
 * Runnable (needs `anvil` from Foundry): deploy the OFFICIAL ERC-8004 Identity + Validation registries on a local
 * chain, register an agent, request validation from FractalAI, respond with a post-quantum receipt, verify it.
 *   node examples/erc8004-validator.ts
 */
import { foundry } from 'viem/chains';
import { receiptBytes, utf8, sha256Of } from '../src/core.ts';
import { VALIDATION_REGISTRY_ABI, REQUEST_SCHEMA, requestPayloadBytes, keccakOf, issueValidationReceipt, responseArgs, verifyValidation } from '../src/erc8004.ts';
import { testTrust } from '../src/testing.ts';
import { startChain, registerAgent, dataUri, fromDataUri } from '../test/erc8004-helpers.ts';

const T = testTrust();
const C = await startChain(28545);
try {
  const [, agentW, validatorW] = C.wallets;
  const output = utf8('{"summary":"Revenue +12% QoQ"}');
  const agentId = await registerAgent(C, agentW, 'https://agent.example/card.json');
  const payload = requestPayloadBytes({
    schema: REQUEST_SCHEMA, chain: `eip155:${foundry.id}`, identity_registry: C.identity.toLowerCase(), agent_id: agentId.toString(),
    validator: validatorW.account!.address.toLowerCase(), output: { sha256: sha256Of(output), media_type: 'application/json' },
    payment: { scheme: 'x402-exact', network: 'eip155:8453', tx_hash: '0x' + '5a'.repeat(32) },
  });
  const requestHash = keccakOf(payload);
  const reqTx = await agentW.writeContract({ address: C.validation, abi: VALIDATION_REGISTRY_ABI, functionName: 'validationRequest', args: [validatorW.account!.address, agentId, dataUri(payload), requestHash], account: agentW.account!, chain: foundry });
  await C.pub.waitForTransactionReceipt({ hash: reqTx });

  const receipt = await issueValidationReceipt({ chainId: foundry.id, validationRegistry: C.validation, identityRegistry: C.identity, agentId, requestHash, validator: validatorW.account!.address }, fromDataUri(dataUri(payload)), output, T.issuer.signer);
  const served = receiptBytes(receipt);
  const resTx = await validatorW.writeContract({ address: C.validation, abi: VALIDATION_REGISTRY_ABI, functionName: 'validationResponse', args: responseArgs(requestHash, receipt, dataUri(served)), account: validatorW.account!, chain: foundry });
  await C.pub.waitForTransactionReceipt({ hash: resTx });

  const d = await verifyValidation(C.pub, C.validation, requestHash, served, T.opts, output);
  console.log(JSON.stringify({ identityRegistry: C.identity, validationRegistry: C.validation, agentId: agentId.toString(), requestHash, validationRequestTx: reqTx, validationResponseTx: resTx, accepted: d.accepted, levels: d.verdict.levels, profile: d.profile }, null, 2));
} finally {
  C.stop();
}
