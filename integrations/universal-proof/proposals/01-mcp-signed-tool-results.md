# DRAFT — not submitted. Target: MCP community (Discord → Working/Interest Group sponsor, then a SEP)

**Title:** Convention for post-quantum signed tool results in `_meta` (no protocol change)

**Author:** John Edward Romo Sanchez (FractalAI, KPITAPP SAS). Drafted with AI assistance (Claude); reviewed and submitted by the author.
**Status of the work:** reference implementation and tests exist; not deployed in production; no external audit.

## Problem

A `CallToolResult` (`content`, `structuredContent`) reaches the client unsigned. When a tool is paid, the de facto
x402 transport places the settlement in `_meta["x402/payment-response"]`, which is also unsigned. This was raised in the
closed proposal #3354 ("verifiable tool results"): structured content is unattested and payment data is malleable.

## Proposal (a convention, not a spec change)

A server MAY attach a receipt under `_meta["co.net.fractalai/receipt"]`. The key follows the `_meta` prefix rules
(reverse DNS, not reserved). The receipt is an ML-DSA-65 (FIPS 204) signature over
`sha256(JCS({content, structuredContent?, isError}))`, the tool name, `sha256(JCS(arguments))` and, when present,
`sha256(JCS(_meta["x402/payment-response"]))`. `_meta` itself is excluded from the digest.

Clients that do not know the key ignore it. Clients that do know it verify the receipt with an open verifier and
recompute the three hashes from the call they made and the result they received.

## Evidence

- Implementation: `src/mcp.ts`. Tests: `test/mcp.test.ts`. They run against the official `@modelcontextprotocol/sdk`
  1.32.1 (`Server` + `Client` over `InMemoryTransport`).
- The receipt survives the SDK round-trip. Tampering with `structuredContent`, swapping the payment-response,
  replaying the receipt with other arguments, or removing it is detected (5/5).
- Verifier: Trust Kernel v2, spec 2.2, kind `agent-commerce-receipt`. It is an open specification with two
  implementations (JS and Python) and an adversarial corpus of 217 vectors that both pass.

## Limits

- The receipt proves that the server's key bound this result to this call at time T. It does not prove that the
  result is true.
- Key distribution relies on a signed, epoch-chained key directory. No production `commerce-receipt` key is
  published yet.
- The official TS SDK negotiates `2025-11-25`. The convention only uses `_meta`, which works the same way in
  `2026-07-28`.

## Ask

A sponsor to discuss whether a generic `_meta` receipt convention (algorithm-agnostic, with ML-DSA-65 as one profile)
belongs in an MCP extension.
