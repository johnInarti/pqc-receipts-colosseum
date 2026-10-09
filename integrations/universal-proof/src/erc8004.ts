/**
 * Profile `erc8004.validation/1` — FractalAI as an ERC-8004 VALIDATOR that publishes post-quantum receipts.
 *
 * ERC-8004 (Draft) Validation Registry, official implementation erc-8004/erc-8004-contracts:
 *   validationRequest(validatorAddress, agentId, requestURI, requestHash)            — agent owner/operator
 *   validationResponse(requestHash, response, responseURI, responseHash, tag)        — the named validator only
 *   getValidationStatus(requestHash) → (validator, agentId, response, responseHash, tag, lastUpdate)
 * The spec says requestHash is "keccak256 of the request payload" and responseHash "its commitment".
 *
 * What FractalAI checks before responding (and what `response = 100` MEANS here — nothing more):
 *   1. keccak256(bytes at requestURI) == requestHash
 *   2. the request payload names this chain, this Identity Registry, this agentId and this validator
 *   3. sha256(delivered output) == payload.output.sha256
 * Then it issues an agent-commerce-receipt binding chain/registries/agentId/requestHash/validator + the payment the
 * payload declares (copied, NOT settled-checked by this profile) + the output hash, and responds with
 * responseURI → receipt, responseHash = keccak256(JCS(receipt)), tag = "fractalai-pqc-receipt/1".
 * It does NOT attest the quality or correctness of the agent's work.
 */
import { keccak256, getAddress } from 'viem';
import type { Address, Hex, PublicClient } from 'viem';
import { jcs, sha256Of, utf8, makeBody, issueReceipt, verifyReceipt, profileCheck, decide, signedBody, receiptBytes } from './core.ts';
import type { CommerceBody, CommerceReceipt, Signer, TrustOptions, ProfileCheck, Decision } from './core.ts';

export const ERC8004_PROTOCOL = 'erc8004';
export const ERC8004_PROFILE = 'erc8004.validation/1';
export const ERC8004_TAG = 'fractalai-pqc-receipt/1';
export const REQUEST_SCHEMA = 'fractalai.erc8004-validation-request/1';

/** Minimal ABI of the official ValidationRegistryUpgradeable (functions used here, signatures verified against source). */
export const VALIDATION_REGISTRY_ABI = [
  { type: 'function', name: 'validationRequest', stateMutability: 'nonpayable', inputs: [{ name: 'validatorAddress', type: 'address' }, { name: 'agentId', type: 'uint256' }, { name: 'requestURI', type: 'string' }, { name: 'requestHash', type: 'bytes32' }], outputs: [] },
  { type: 'function', name: 'validationResponse', stateMutability: 'nonpayable', inputs: [{ name: 'requestHash', type: 'bytes32' }, { name: 'response', type: 'uint8' }, { name: 'responseURI', type: 'string' }, { name: 'responseHash', type: 'bytes32' }, { name: 'tag', type: 'string' }], outputs: [] },
  { type: 'function', name: 'getValidationStatus', stateMutability: 'view', inputs: [{ name: 'requestHash', type: 'bytes32' }], outputs: [{ name: 'validatorAddress', type: 'address' }, { name: 'agentId', type: 'uint256' }, { name: 'response', type: 'uint8' }, { name: 'responseHash', type: 'bytes32' }, { name: 'tag', type: 'string' }, { name: 'lastUpdate', type: 'uint256' }] },
  { type: 'function', name: 'getIdentityRegistry', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
] as const;

/** The request document an agent publishes at requestURI (its keccak256 is the on-chain requestHash). */
export interface ValidationRequestPayload {
  schema: typeof REQUEST_SCHEMA;
  chain: string;               // CAIP-2, e.g. eip155:8453
  identity_registry: string;   // lowercase address
  agent_id: string;            // decimal
  validator: string;           // lowercase address
  output: { sha256: string; media_type?: string; uri?: string };
  payment: Record<string, string>; // e.g. { scheme: 'x402-exact', network: 'eip155:8453', tx_hash: '0x…' }
  job?: Record<string, string>;
}

export const requestPayloadBytes = (p: ValidationRequestPayload): Uint8Array => utf8(jcs(p));
export const keccakOf = (b: Uint8Array): Hex => keccak256(b);
const lc = (a: string) => getAddress(a).toLowerCase();

export interface ValidationContext {
  chainId: number;
  validationRegistry: Address;
  identityRegistry: Address;
  agentId: bigint;
  requestHash: Hex;
  validator: Address;
}

/** Validator side, steps 1–3 of the header; returns the body to sign or throws with the reason to answer 0. */
export function buildValidationBody(ctx: ValidationContext, requestBytes: Uint8Array, deliveredOutput: Uint8Array, issuedAt?: number): CommerceBody {
  if (keccakOf(requestBytes).toLowerCase() !== ctx.requestHash.toLowerCase()) throw new Error('keccak256(request payload) != requestHash');
  const p = JSON.parse(new TextDecoder().decode(requestBytes)) as ValidationRequestPayload;
  if (p.schema !== REQUEST_SCHEMA) throw new Error(`request schema is not ${REQUEST_SCHEMA}`);
  if (p.chain !== `eip155:${ctx.chainId}`) throw new Error('request names another chain');
  if (lc(p.identity_registry) !== lc(ctx.identityRegistry)) throw new Error('request names another identity registry');
  if (p.agent_id !== ctx.agentId.toString()) throw new Error('request names another agentId');
  if (lc(p.validator) !== lc(ctx.validator)) throw new Error('request names another validator');
  const outSha = sha256Of(deliveredOutput);
  if (p.output?.sha256 !== outSha) throw new Error('delivered output does not match request.output.sha256');
  return makeBody({
    protocol: ERC8004_PROTOCOL, profile: ERC8004_PROFILE, issued_at: issuedAt,
    payment: { ...p.payment },
    bindings: {
      chain_id: `eip155:${ctx.chainId}`, validation_registry: lc(ctx.validationRegistry), identity_registry: lc(ctx.identityRegistry),
      agent_id: ctx.agentId.toString(), request_hash: ctx.requestHash.toLowerCase(), validator: lc(ctx.validator),
    },
    delivery: { sha256: outSha, ...(p.output.media_type ? { media_type: p.output.media_type } : {}), size: deliveredOutput.length },
  });
}

export async function issueValidationReceipt(ctx: ValidationContext, requestBytes: Uint8Array, deliveredOutput: Uint8Array, signer: Signer, issuedAt?: number): Promise<CommerceReceipt> {
  return issueReceipt(buildValidationBody(ctx, requestBytes, deliveredOutput, issuedAt), signer);
}

/** Arguments for validationResponse. responseHash commits to the exact bytes served at responseURI. */
export function responseArgs(requestHash: Hex, receipt: CommerceReceipt, responseURI: string): readonly [Hex, number, string, Hex, string] {
  return [requestHash, 100, responseURI, keccakOf(receiptBytes(receipt)), ERC8004_TAG] as const;
}

export interface OnchainValidation { validator: Address; agentId: bigint; response: number; responseHash: Hex; tag: string; lastUpdate: bigint; identityRegistry: Address; chainId: number }

export async function readValidation(client: PublicClient, registry: Address, requestHash: Hex): Promise<OnchainValidation> {
  const [validator, agentId, response, responseHash, tag, lastUpdate] = await client.readContract({ address: registry, abi: VALIDATION_REGISTRY_ABI, functionName: 'getValidationStatus', args: [requestHash] });
  const identityRegistry = await client.readContract({ address: registry, abi: VALIDATION_REGISTRY_ABI, functionName: 'getIdentityRegistry' });
  const chainId = await client.getChainId();
  return { validator, agentId, response, responseHash, tag, lastUpdate, identityRegistry, chainId };
}

/** Relying-party profile check: the signed bindings must equal what the registry says, and the served bytes hash to responseHash. */
export function checkValidation(body: CommerceBody, onchain: OnchainValidation, registry: Address, requestHash: Hex, servedReceiptBytes: Uint8Array, deliveredOutput?: Uint8Array): ProfileCheck {
  const c = profileCheck(ERC8004_PROFILE);
  const b = body.bindings;
  c.check(body.protocol === ERC8004_PROTOCOL && body.profile === ERC8004_PROFILE, 'profile', `profile is ${body.protocol}/${body.profile}`);
  c.check(keccakOf(servedReceiptBytes).toLowerCase() === onchain.responseHash.toLowerCase(), 'responseHash', 'keccak256(served receipt) != on-chain responseHash (receipt substituted?)');
  c.check(onchain.tag === ERC8004_TAG, 'tag', `on-chain tag is ${onchain.tag}`);
  c.check(onchain.response === 100, 'response', `on-chain response is ${onchain.response}`);
  c.check(b.chain_id === `eip155:${onchain.chainId}`, 'chain_id', 'receipt names another chain');
  c.check(b.validation_registry === lc(registry), 'validation_registry', 'receipt names another validation registry');
  c.check(b.identity_registry === lc(onchain.identityRegistry), 'identity_registry', 'receipt names another identity registry');
  c.check(b.agent_id === onchain.agentId.toString(), 'agent_id', 'receipt names another agent');
  c.check(b.request_hash === requestHash.toLowerCase(), 'request_hash', 'receipt is for another request');
  c.check(b.validator === lc(onchain.validator), 'validator', 'the on-chain validator is not the one named in the receipt');
  if (deliveredOutput) c.check(body.delivery.sha256 === sha256Of(deliveredOutput), 'delivery.sha256', 'output does not match the signed delivery hash');
  return c.result();
}

/** Full relying-party decision from chain state + the bytes served at responseURI. */
export async function verifyValidation(client: PublicClient, registry: Address, requestHash: Hex, servedReceiptBytes: Uint8Array, trust: TrustOptions, deliveredOutput?: Uint8Array): Promise<Decision> {
  const onchain = await readValidation(client, registry, requestHash);
  const verdict = await verifyReceipt(servedReceiptBytes, trust);
  const body = signedBody(verdict);
  return decide(verdict, body ? checkValidation(body, onchain, registry, requestHash, servedReceiptBytes, deliveredOutput) : null);
}
