# DRAFT — not submitted. Target: Ethereum Magicians thread "ERC-8004: Trustless Agents" (https://ethereum-magicians.org/t/erc-8004-trustless-agents/25098)

**Title:** A validator profile for ERC-8004: post-quantum receipts that bind requestHash, payment and output

**Author:** John Edward Romo Sanchez (FractalAI, KPITAPP SAS). Drafted with AI assistance (Claude).

## Summary

We implemented a validator against the official `ValidationRegistryUpgradeable` (erc-8004/erc-8004-contracts
@ `b9e466c2`, unmodified). It answers `validationRequest` as follows:

- `responseURI` → an ML-DSA-65 (FIPS 204) receipt document;
- `responseHash = keccak256(JCS(receipt))`;
- `tag = "fractalai-pqc-receipt/1"`.

The receipt binds `chain`, Validation and Identity registries, `agentId`, `requestHash`, validator, the payment the
request declares, and `sha256(output)`.

## Semantics of `response = 100` (deliberately narrow)

1. `keccak256(bytes at requestURI) == requestHash`.
2. The request names this chain, this Identity Registry, this `agentId` and this validator.
3. `sha256(delivered output) == request.output.sha256`.

It does **not** assess quality, and it does not verify payment settlement. The payment fields are copied from the
request and bound into the receipt; settlement checks belong to a separate profile.

## Evidence

`src/erc8004.ts` and `test/erc8004.test.ts` (5/5) run on anvil with the official Identity and Validation registries
deployed behind ERC1967 proxies, as in the official test suite. The tests cover:

- the full flow, with third-party verification from chain state plus the served bytes;
- a substituted receipt, rejected through the `responseHash` mismatch;
- a non-validator responding, reverted by the contract;
- an altered request payload;
- a wrong output.

## Questions for the authors

- Is there a target date and address for a canonical Validation Registry deployment? The README pins Identity and
  Reputation only.
- Would a registry of `tag` values (for example, a `<org>-<scheme>/<version>` convention) help indexers distinguish
  validation semantics?
- Until the Validation Registry is deployed, is `feedbackURI` plus `feedbackHash` the recommended place for
  payment-bound evidence? It already carries `proofOfPayment`.

## Limits

- No production signing key with use `commerce-receipt` is published yet.
- The validator in this test is an EOA. A contract validator exists in our monorepo
  (`FractalProofOfDecisionValidator8004`) but is not deployed.
