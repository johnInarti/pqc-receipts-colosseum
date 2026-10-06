/**
 * Self-attest mode: a `ResourceServerExtension` (the interface @x402/core's `x402ResourceServer`
 * defines for third parties to hook into `enrichSettlementResponse`) that adds a ML-DSA-65
 * (FIPS 204) integrity seal to every settle response, signed with a key the SELLER controls.
 *
 * WHAT THIS PROVES: the settlement facts (payer, amount, network, transaction, response hash)
 * were not altered after settle-time, and will remain checkable after CRQC timelines make
 * classical signatures worthless. WHAT THIS DOES NOT PROVE: that FractalAI (or anyone but the
 * seller) attests to it — the seller could mint any seal for anything with a key they hold.
 * For an actual independent third party attestation, use notary.mjs instead.
 *
 * Usage (one line, per the official extension pattern):
 *   import { createSelfAttestExtension } from '@fractalai/x402-pqc-witness/self-attest';
 *   const server = new x402ResourceServer(facilitator)
 *     .register('eip155:8453', new ExactEvmScheme())
 *     .registerExtension(createSelfAttestExtension({ secretKey, publicKey }));
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { buildSealBody, signSeal, SELF_ATTEST_DOMAIN } from './witness-core.mjs';

export const SELF_ATTEST_KEY = 'fractalai-x402-seal';

/** Generates a fresh ML-DSA-65 keypair (keygen() sources its own 32-byte seed from the platform CSPRNG when none is given). */
export function generateKeypair() {
  return ml_dsa65.keygen();
}

/**
 * @param {{ secretKey: Uint8Array, publicKey: Uint8Array, key?: string }} opts
 * @returns a ResourceServerExtension (per @x402/core's `types.ts`): { key, enrichSettlementResponse }
 */
export function createSelfAttestExtension({ secretKey, publicKey, key = SELF_ATTEST_KEY }) {
  if (!secretKey || !publicKey) {
    throw new Error('createSelfAttestExtension requires { secretKey, publicKey } — generate one with generateKeypair() and persist it (a new key on every restart breaks verifiability across restarts).');
  }
  return {
    key,
    async enrichSettlementResponse(_declaration, context) {
      // context: SettleResultContext = { paymentPayload, requirements, declaredExtensions, phase, transportContext, result }
      const transport = context?.transportContext;
      const responseBody = transport && typeof transport === 'object' ? transport.responseBody : null;
      const resource = transport?.request?.routePattern ?? transport?.request?.path ?? null;
      const body = buildSealBody({
        resource,
        requirements: context?.requirements,
        result: context?.result,
        responseBody,
      });
      return signSeal(body, { domain: SELF_ATTEST_DOMAIN, secretKey, publicKey });
    },
  };
}
