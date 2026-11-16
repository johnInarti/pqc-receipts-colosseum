# x402 settlement outcomes: what each answer means and how to recover

For the payer. One rule matters most: **once you have signed an authorization, we never answer with a new
offer.** A 402 offers `accepts[]` again in the body and in the `PAYMENT-REQUIRED` header, and an x402 client that reads
that header pays a second time. So when the fate of your payment is unclear we answer 202 or 409, never 402.

## Answers

| HTTP | What happened | What to do |
|---|---|---|
| **200** | You paid and the product is in the body. | Nothing. |
| **402** | You have not paid yet, or your authorization was not valid. Carries `accepts[]`. | Sign and retry. |
| **409** `authorization_already_used` | That `(from, nonce)` was already presented, here or on another of our routes. One signed authorization buys exactly one product. | Sign a NEW authorization with another nonce. |
| **409** `settlement_reverted` | The transfer reverted on chain. **Nothing was charged.** Carries the hash. | Sign a new authorization. |
| **202** `settlement_reconciliation_required` **with a hash** | A transfer was broadcast and its result is not confirmed. | **Do not sign another.** Watch that hash; if it was mined, redeem it with `X-PAYMENT = {txHash}`. |
| **202** `settlement_reconciliation_required` **without a hash** | An external facilitator was settling, its answer was lost, and the chain says your authorization is consumed (`authorization_state: "consumed"`) or could not be read (`"unknown"`). | **Do not pay again.** If `consumed`, you were charged once: find the USDC transfer from your address to the route's pay-to address and redeem it with `X-PAYMENT = {txHash}`. If `unknown`, retry the same call in a few seconds. |
| **503** | Our anti-replay store is not answering. Nothing was charged or delivered. | Retry. |

No 202 or 409 carries `accepts[]`, `asset` or `payTo` in an offer structure. That is deliberate.

## Limits of the direct-transfer (txHash) path

- Redemption is one-time, globally: presenting an already redeemed txHash returns 409.
- It is **not bound to the payer address or to the request**. Whoever presents a valid, unredeemed txHash first
  redeems it. One-time redemption does not prove that the redeemer made the payment.
- The EIP-3009 path is bound to the payer: the authorization is signed by the paying address.
- Treat a txHash as a bearer credential until it is redeemed, and prefer the EIP-3009 path.

## Scope

Receipts are node-local signatures made with our ML-DSA-65 key. They are not backed by chain consensus and they are
not a security certification.
