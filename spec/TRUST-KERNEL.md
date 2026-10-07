# Trust Kernel v2 — normative specification

| | |
|---|---|
| Version | **2.0.0** (2026-10-07) |
| Status | Draft for review. Reference implementation: `kernel/` (JavaScript). Second implementation: `python/src/fractalai_pqc_verify/kernel/`. Executable specification: `corpus/` (both pass 129/129). |
| Supersedes | the per-module trust logic of `verifier/` and `conformance/` ≤ 0.3 (they now delegate here) |
| Keywords | MUST, MUST NOT, SHOULD, MAY as in RFC 2119 / RFC 8174 |

## 1. Purpose and scope

This document defines the single algorithm that decides whether a FractalAI post-quantum signed receipt
(ML-DSA-65, FIPS 204) is trustworthy, at which level, and why. Every verifier FractalAI publishes (Node
verifier, conformance suite, GitHub Action, Python package) MUST either call an implementation of this
algorithm or reproduce it and pass the corpus at 100 %.

A verdict states facts about **bytes, keys and time**. It never states that the *content* of a receipt is true
(a MIDAS alert proves FractalAI's key signed those numbers at that time, not that the position will be
liquidated).

## 2. Threat model

The verifier is assumed honest and running correct code. Everything else MAY be hostile:

| Adversary | Controls | Must not achieve |
|---|---|---|
| A1 document forger | every byte of the receipt JSON, including fields that look like metadata (`domain`, `profile`, `served_message`, `facts`, `emitted_at`, `snapshot`, `anchor`) | a verdict level that the signed bytes do not support |
| A2 mirror / CDN / receipt store | which receipt is served for a requested id | substitute another (even genuine) receipt for the one requested |
| A3 key-directory host / TLS MITM | the served directory | trust in a key that the pinned governance key did not publish in an epoch reachable from the pinned checkpoint; rollback; equivocation |
| A4 holder of a compromised or retired receipt key | arbitrary signatures, any signed `emitted_at` | trust after revocation without a consensus time proof that pre-dates the revocation |
| A5 chain participant | deploys contracts, sends transactions, front-runs, squats write-once slots | a time proof from any contract other than the pinned deployment, a time not taken from the block header, an `observedAt` that differs from the signed time |
| A6 RPC operator | every JSON-RPC answer of the endpoints it runs | acceptance when independent RPCs disagree (if more than one is configured); acceptance of another chain/cluster (chain id / genesis); a signer that did not sign (Ed25519 is checked locally) |
| A7 resource attacker | sizes, nesting, slow responses | crash, hang or unbounded memory in the verifier |
| A8 parser-differential attacker | JSON edge cases (duplicate keys, lone surrogates, NaN, unsafe integers, engine bugs) | two implementations reaching different verdicts on the same bytes |

Out of scope (documented limits, §11): an RPC operator that controls **every** configured endpoint (no light
client), compromise of the governance key itself, compromise of the verifier's own code or of
`trust-roots.json` on disk, chain-level attacks (sequencer time manipulation within protocol bounds,
validator collusion on Arc, deep reorgs past finality).

## 3. Definitions

- **Signed bytes / signed message**: the exact UTF-8 octets passed to ML-DSA-65 Verify (empty context).
- **Kind**: one row of the domain table (§5). The kind is **chosen by the caller's policy**, never by the document.
- **Signed projection** (`signed`): the data returned to the caller, derived exclusively from the signed bytes (or
  from content committed by a signed hash, e.g. `snapshot` via `snapshot_hash`).
- **Signed time** (`T_s`): the time the signer put inside the signed bytes (`emitted_at` in a MIDAS canonical,
  `sealed_at` in a seal body), as unix seconds. Kinds without one have `T_s = null`.
- **Trust roots**: `kernel/trust-roots.json` — pinned governance key, pinned directory checkpoint (epoch 3,
  root `8748d4d6…88d7`, verified 2026-10-07), pinned anchor deployments (`chainId → contract, runtime code
  hash`), Solana cluster genesis hashes, announced anchor signers, known anchorers. Plus
  `kernel/checkpoint-directory.json`, the full body of the checkpoint epoch.
- **Override**: any caller-supplied replacement of a trust root (`roots`, `governanceKey`, `trustedKeys`,
  `allowTlsDirectory`, `solanaSigners`, `allowObjectInput`). Overrides are legal and MUST be reported.

## 4. Only what is signed

4.1 An implementation MUST rebuild the signed message from the kind's fixed domain (§5) and the signed content.
It MUST NOT read the message, the domain, the route or the kind from the document.

4.2 Unsigned fields that duplicate signed content MUST match it exactly, else `integrity` fails
(`UNSIGNED_FIELD_MISMATCH`, `RECEIPT_ID_MISMATCH`, `SIGNED_MESSAGE_MISMATCH`, `DOMAIN_MISMATCH`,
`SNAPSHOT_MISMATCH`): `receipt_id`/`content_id` = sha256(canonical); `served_message` = rebuilt message;
`served_domain`/`domain` = the kind's domain (MIDAS also allows the canonical header); top-level `emitted_at`
= the signed one (as a number); `facts` has exactly the canonical's keys, each equal (strings exactly, booleans
as `true`/`false`, `null`, numbers compared as IEEE-754 doubles after parsing the canonical decimal); `snapshot`
satisfies sha256(JCS(snapshot)) = signed `snapshot_hash`.

4.3 Signed JSON (seal bodies, ACP decisions) is canonicalised with RFC 8785 and MUST contain only strings,
booleans, null, arrays, objects and **safe integers** (|n| ≤ 2^53−1); anything else is `SIGNED_JSON_NUMBER`.
This is the subset every runtime canonicalises identically.

4.4 Fields that duplicate nothing are ignored and listed in `ignored_unsigned_fields`; they never influence the
verdict. Anchor references are hints (§7) and are never part of the projection.

4.5 A document that carries the distinctive fields of two kinds (`canonical`/`receipt_id`/`served_message`/
`facts`/`snapshot` vs `body` vs `decision` vs `route_id`/`digest`), or whose optional `profile` label does not
name the verified kind, MUST be refused (`KIND_AMBIGUOUS`).

## 5. Domain table (normative)

| Kind | Signed message | Allowed key `use` | Trust source | Signed time |
|---|---|---|---|---|
| `midas-alert` | `FRACTALAI-x402-served-v1\nmidas-alert\n` + sha256hex(canonical) | `x402-receipt` | directory | canonical `emitted_at=` |
| `x402-seal` (notary) | `FRACTALAI-x402-served-v1\nx402-witness\n` + sha256hex(JCS(body)) | `x402-receipt` | directory | `body.sealed_at` |
| `acp-verdict` | `FRACTALAI-x402-served-v1\nx402-attest-decision\n` + sha256hex(JCS(decision)) | `x402-receipt` | directory | — |
| `served-proof` | `FRACTALAI-x402-served-v1\n<route>\n<digest>`, route ∉ {midas-alert, x402-witness, x402-attest-decision}, route `^[a-z0-9][a-z0-9-]{0,63}$`, digest 64 lowercase hex | `x402-receipt` | directory | — |
| `self-attest-seal` | `FRACTALAI-x402-self-attest-v1\n` + sha256hex(JCS(body)) | none | explicit pinned key set only | `body.sealed_at` |
| key directory | `FRACTALAI-key-directory-v1\n` + root | governance key (never listed as a receipt key) | trust roots | — |

MIDAS canonical: first line `FRACTALAI-midas-alert-v1`, then `key=value` lines, keys `^[a-z][a-z0-9_]{0,63}$`,
no duplicates, no CR/NUL/U+2028/U+2029, ≤ 8 KiB, all of `address chain_id health_factor threshold collateral_usd
debt_usd risk_tier observed_at source snapshot_hash emitted_at` present, `emitted_at` a canonical decimal.
`sealed_at`: `YYYY-MM-DDTHH:MM:SS(.sss)?Z`, a real calendar time; `T_s` = floor(seconds).

## 6. Key directory

6.1 **Epoch check** (`checkEpoch`): `spec = FRACTALAI-key-directory-v1`; `epoch` positive safe integer; `root`,
`prev_root` 64 lowercase hex (epoch 1 ⇒ zero prev_root); `keys` a non-empty list (≤ 256) of objects, each with
canonical-base64 1952-byte `public_key_b64`, `kid = sha256(public_key_b64)[:16]`, string `use`, `status ∈
{reserved, active, retiring, retired, revoked}`, `not_before`/`not_after`/`revoked_at`/`added_at` absent, null or
non-negative safe integers; no key or kid listed twice; the governance key not listed as a key;
`root = sha256(JCS({epoch, prev_root, governance_key, keys sorted by kid}))`; `signed_message`, if present, equals
the rebuilt one; the governance ML-DSA-65 signature verifies; the signer equals the pinned governance key.
Any failure: `DIRECTORY_INVALID` (or `DIRECTORY_SIGNER_NOT_PINNED`).

6.2 **Chain and anti-rollback** against checkpoint `(E_c, R_c)`:
- `epoch < E_c` → `DIRECTORY_ROLLBACK`;
- `epoch = E_c` → root MUST equal `R_c` (`DIRECTORY_EQUIVOCATION`);
- `epoch > E_c` → every epoch `E_c+1 … epoch−1` MUST be supplied (`DIRECTORY_CHAIN_GAP`), each passes 6.1 with
  the same signer, `prev_root(e) = root(e−1)` (`DIRECTORY_CHAIN_BREAK`), and from the checkpoint body onward the
  history is append-only: no kid removed, no key/use rebound, status transitions only
  `reserved→{active,revoked}`, `active→{retiring,retired,revoked}`, `retiring→{retired,revoked}`,
  `retired→revoked`; `not_before` and `revoked_at` immutable once set; `not_after` never extended
  (`DIRECTORY_NOT_APPEND_ONLY`).
- With an override governance key the baked checkpoint does not apply (a caller MAY supply its own). With
  `allowTlsDirectory` the signer is not pinned and `trust_basis = "tls"`.

6.3 **Lifecycle** (`keyAuthorizes`), evaluated at `T = T_s` (or at verification time `now` if the kind signs no time):
- `use` MUST be allowed for the kind (§5) — `KEY_USE_MISMATCH`;
- `T_s > now + skew` → `SIGNED_TIME_IN_FUTURE` (skew default 900 s);
- `reserved` → never; `active` → `not_before ≤ T ≤ (not_after ?? ∞)`, `not_before` required;
- `retiring`/`retired` → only with a signed time, `not_before ≤ T ≤ not_after`, both required;
- `revoked` → only if `revoked_at` is set **and** a counted consensus anchor (§7) has time `T_a < revoked_at`
  and `T ≤ T_a + skew`. The signed time alone never rescues a revoked key (its holder can sign any time).

## 7. Time proofs from consensus

7.1 Anchor references (`receipt.anchor`, `receipt.anchors[]` or caller-supplied, ≤ 8) are **hints**. Every fact
comes from the chain and the trust roots. On-chain ids: `receipt_id = sha256(signature bytes)`,
`payload_hash = sha256(signed message)`, `kid16 = sha256(public_key_b64)[:16]`. Anchoring requires `T_s`.

7.2 **EVM** (`fractalai.pqc-receipt-anchor/1`, `PQCReceiptAnchor`). For each configured RPC URL, in order:
`eth_chainId` = chain id; `eth_getCode(pinned contract,"latest")` and keccak256 = pinned runtime code hash
(`0xe4733ce5…f2595`); locate exactly one `ReceiptAnchored(receiptId)` log from the pinned contract — via
`eth_getTransactionReceipt(tx_hash)` (status `0x1`, optional `log_index`) or `eth_getLogs({address, topics:
[topic, receiptId], fromBlock, toBlock})` with `fromBlock = toBlock = block_number` when hinted, else
`from_block … latest`; log not `removed`, 4 topics, 96 data bytes with canonical padding, `blockHash` present;
`topics[2] = payload_hash` (else `ANCHOR_SQUATTED`, naming the occupant), `topics[3] = kid16‖0…`;
`eth_getBlockByNumber(blockNumber,false)`: `hash = log.blockHash`, `number` equal; `time := header.timestamp`
and event `anchoredAt` MUST equal it; event `observedAt` MUST equal `T_s`; `T_s ≤ time + skew`;
`eth_blockNumber − block + 1 ≥ minConfirmations`; `finalized := eth_getBlockByNumber("finalized").number ≥ block`.
A reference naming another contract is `ANCHOR_CONTRACT_NOT_PINNED`; an unpinned chain is
`ANCHOR_CHAIN_NOT_PINNED`. Quantities are sent as lowercase `0x` hex without leading zeros.

7.3 **Solana** (SPL Memo v2). For each RPC URL: `getGenesisHash` = pinned genesis of the named cluster;
`getTransaction(sig,{encoding:"base64",commitment:"finalized",maxSupportedTransactionVersion:0})` non-null,
`meta.err = null`, `blockTime` a positive integer (`SOL_NO_BLOCKTIME` otherwise);
`getSignatureStatuses([sig],{searchTransactionHistory:true})` finalized, `err = null`, same slot; parse the raw
wire bytes with bounds checks (legacy or v0, no trailing bytes, minimal shortvecs); exactly one signature equal
to the requested one; no address lookup tables; Ed25519 verified **locally** over the message; signer ∈
announced signers of that cluster; exactly one instruction, program Memo v2, listing the signer; memo bytes ==
`fractalai.pqc-receipt-anchor/1|rid=<receipt_id>|ph=<payload_hash>|kid=<kid16>|obs=<T_s>` byte for byte;
`T_s ≤ blockTime + skew`. `finalized = true` (finalized commitment).

7.4 **Multi-RPC**: the check runs independently on every configured URL; all MUST succeed and agree on the facts
(EVM: block number/hash/time/observedAt/anchoredBy/tx/logIndex; Solana: slot/blockTime/signer/sha256(wire)),
else `RPC_DISAGREEMENT`. `policy.rpcQuorum` is the minimum number of URLs (`RPC_QUORUM`). `finalized` is true only
if every RPC reports it.

7.5 **Counting**: an anchor counts if verified AND (its network class is `production` or
`policy.allowTestnetAnchors`) AND (anchorer known or not `policy.requireKnownAnchorer`). `time_anchored` = some
anchor counts; `T_a` = earliest counted time; `finalized` = some counted anchor finalized. Test networks remain
marked `network_class: "test"` in the facts.

## 8. Input / output hygiene

8.1 JSON MUST be parsed by a strict RFC 8259 parser that refuses duplicate keys (`JSON_DUPLICATE_KEY`), lone
surrogates (`JSON_LONE_SURROGATE`), NaN/Infinity/out-of-range numbers, a BOM and trailing data (`JSON_INVALID`),
depth > 32 (`JSON_TOO_DEEP`), > 100 000 nodes or > 2 MiB (`JSON_TOO_LARGE`). Callers SHOULD pass raw text.

8.2 Base64 MUST be canonical RFC 4648 (padded, standard alphabet, zero pad bits, re-encoding round-trips); key
1952 bytes, signature 3309 bytes. Base58 MUST round-trip.

8.3 Network: https only (http only for loopback), no redirects, JSON content type, ONE deadline raced against
headers and body (default 20 s), streamed byte cap (2 MiB, RPC 4 MiB). Never retry into "valid".

8.4 Load-time self-tests: (a) ML-DSA-65 known-answer test on the production signature of receipt `fe62b072…`
(genuine → `true`, flipped signature and other message → `false`); (b) JSON key-cache self-test of the
implementation's own parser after priming the engine's native parser. If (a) or (b) fails the implementation
MUST refuse every verification (`ENGINE_SELFTEST_FAILED`). If the engine's *native* JSON parser fails the probe,
the implementation MUST refuse already-parsed object input unless `allowObjectInput` is set (an override); raw
text input remains safe because it never reaches the native parser.

8.5 Output: every untrusted string shown to a human or a CI log MUST be escaped to one line without C0/C1
controls, bidi overrides or U+2028/U+2029, and bounded in length.

## 9. Decision algorithm

Input: receipt (text or object), options. Output: the verdict of §9.2. The algorithm MUST NOT throw.

1. If self-tests failed → refuse. Normalise the policy (`require` ⊆ LEVELS, `integrity` always included).
2. **integrity**: parse (§8.1, defensive copy); the policy MUST name the expected kind(s) (`KIND_UNKNOWN`); with
   several, the shape selects one that MUST be allowed (`KIND_NOT_ALLOWED`); refuse ambiguity (§4.5); parse the
   kind (§4, §5); if `expectedId` is given it MUST equal the content id (`EXPECTED_ID_MISMATCH`).
3. **authentic**: ML-DSA-65 Verify(public key, rebuilt message, signature) (`SIGNATURE_INVALID`). Only now is
   `signed` (the projection) exposed.
4. **time proofs** (if `checkAnchors` or the policy requires `time_anchored`/`finalized`): §7.
5. **trusted**: with `trustedKeys` (override) — non-empty list, key ∈ list, signed time not in the future.
   Otherwise: self-attest seals → `SELF_ATTEST_NOT_TRUSTED`; a directory is required (`NO_TRUST_SOURCE`);
   verify it (§6.1, §6.2) against the roots; the signing key MUST be listed (`KEY_NOT_LISTED`) and authorized
   (§6.3, with `T_a` from step 4).
6. `valid` = every required level is `true`; `exit_code` = 0 if valid, else the code of the first required level
   that is not `true`.

9.2 Verdict:
```
{ kernel, spec_version, kind, valid,
  levels: { integrity, authentic, trusted, time_anchored, finalized },   // true | false | null (not evaluated)
  trust_basis: "pinned-root" | "override" | "tls" | "none",
  key: { kid, use, status, not_before, not_after, revoked_at, evaluated_at, time_basis: signed|verification-time|anchor },
  directory: { epoch, root, chain_epochs, checkpoint_epoch }, signed, signed_time,
  anchors: [ { ref, ok, counts, facts, reason } ], overrides: [..], ignored_unsigned_fields: [..],
  reasons: [ { level, code, detail } ], exit_code, engine: { self_test_ok, native_json_key_cache_ok } }
```
Exit codes: 0 valid · 10 integrity · 11 authentic · 12 trusted · 13 time_anchored · 14 finalized · 2 usage · 3 input.

## 10. Anchor before publish (anti-squatting)

`PQCReceiptAnchor` v1 (deployed, immutable) keys its write-once slot by `receiptId` alone; `receiptId` is public as
soon as the receipt is. Hence:

1. The issuer MUST anchor (and wait for the inclusion of) a receipt **before** serving it publicly.
2. The issuer SHOULD anchor on at least two independent pinned deployments (Arbitrum One and Arc) and list all
   references in `anchors[]`; a verifier counts the receipt as time-anchored if **any** reference verifies, and
   reports a squatted slot (`ANCHOR_SQUATTED`, naming the occupant) without failing the others.
3. A third party that anchors the **genuine** bytes first does not break existence-by-time (time comes from the
   header, `observedAt` must equal the signed time); `policy.requireKnownAnchorer` restricts to FractalAI's
   anchorer if desired.
4. `contracts/PQCReceiptAnchorV2.sol` (records namespaced by anchorer, idempotent batches) is a **proposal, not
   deployed**; adopting it requires a new pinned deployment and code hash in the trust roots.

## 11. Limits (honest)

- **RPC / consensus**: without a light client the verifier believes the configured RPCs about logs, headers and
  finality. Multi-RPC agreement raises the bar to "all configured operators collude". Arbitrum block time is set
  by the sequencer within `maxTimeVariation` (up to 24 h before / 768 s after L1, read 2026-10-06); Arc block time
  by its permissioned validators; Solana `blockTime` is a stake-weighted estimate.
- **Trust roots**: the governance key and checkpoint were pinned on 2026-10-07 from the TLS-served directory
  (trust on first use, made explicit and versioned). The on-chain `FractalCheckpoint` anchor of the directory is
  still pending; until then the roots file itself is the root of trust.
- **Governance key rotation** is not specified in v2: a directory signed by another governance key is refused
  until a signed hand-over format is defined (spec 2.1).
- **Prior epochs**: the public endpoint serves only the latest epoch; epochs after a future epoch 4 will need an
  epoch archive for chain verification (`DIRECTORY_CHAIN_GAP` otherwise).
- **Retired keys** are trusted for receipts whose *signed* time falls in their window; a leaked retired key could
  back-date. Requiring an anchor for keys past `not_after` is a policy decision left open.
- **Cryptography**: `@noble/post-quantum`, `@noble/hashes`, `@noble/curves` (JS); `dilithium-py` / PQClean and
  pure-Python Keccak/Ed25519 (Python). Not a CMVP / FIPS 140-3 validated module. No external audit of this
  kernel; internal adversarial review only (four red-teams, appendix B).
- Python's `bounded_fetch` uses per-socket-operation timeouts (urllib); only the JS fetch enforces a single total
  deadline. The corpus does not depend on either.

## Appendix A — reason codes

See `kernel/src/codes.mjs` (normative list; the Python port's `_codes.py` is generated from it).

## Appendix B — red-team findings → normative rule → corpus vectors

| Finding | Rule | Vectors |
|---|---|---|
| node poc1: directory trusts revoked/reserved/expired keys | §6.3 | `N-RTN1-*`, `N-RTE8-*` |
| node poc2: attacker-chosen seal domain re-wraps acp-verdict | §4.1, §5 | `N-RTN2a/b/c-*` |
| node poc3 / anchor RT-E2: seal-chosen contract, event-data time | §7.2 pinned contract + code hash + header time | `N-RTE2a/b/c-*`, `N-RTE4a-*`, `N-RTN3b-*` |
| node poc4: MIDAS id/facts unbinding | §4.2, §9 step 2 | `N-RTN4a–d-*` |
| node poc5 / action RT-9/11/12: unsigned/lenient directory | §6.1 | `N-RTN5*`, `N-RTA*`, `N-PYF11-*` |
| node poc6: conformance passes with 0 vectors | runner refuses empty/mismatched corpus | `corpus/run.mjs`, `conformance/src/check.mjs` |
| node poc7: foreign domain, digest not hex, "valid" without pin, JCS edge cases | §5, §9 step 5, §4.3, §8.1 | `N-RTN7*`, `N-seal-unsafe-integer`, `N-RTN7c-*` |
| node poc8: hang on slow endpoint | §8.3 raced deadline | kernel unit tests |
| anchor RT-E3/E3b/E11: squatting, front-run copy | §10, §7.5 | `N-RTE3-*`, `P17`, `P18`, `N-RTE3b-*` |
| anchor RT-E4/E5/E6/E7: header, observedAt, cross-RPC, finality | §7.2, §7.4 | `N-RTE4*`, `N-RTE5*`, `N-RTE6*`, `N-RTE7-*` |
| anchor RT-E8/E9: lifecycle evaluated at "now" | §6.3 at signed time; revoked needs anchor | `P11`, `P19`, `N-RTE8-*`, `N-RTN5d-*` |
| anchor RT-E10/S6: non-canonical base64 | §8.2 | `N-RTE10*` |
| anchor RT-S1/S1b/S1c/S2/S3/S4/S5/S7 | §7.3 | `N-RTS*` |
| action RT-5/8/13 | §9 step 5 / step 2 / §6.3 | `N-RTA5-*`, `N-RTA8-*`, `N-RTA13-*` |
| python F1/F1b: profile field re-routes verification | §4.5, kind fixed by policy | `N-PYF1*`, `N-PYF1b-*`, `N-kind-*` |
| python F2: snapshot / extra facts / emitted_at | §4.2 | `N-PYF2a–d-*` |
| python F3/F4/F7/F11, N2 | §8.1, §8.2, §6.1, strict types | `N-PYF4-*`, `N-PYF7-*`, `N-RTE10c-*`, `N-PYN2-*`, `N-PYF11-*` |
| python F8/F8b | §6.3 signed time; malformed lifecycle invalid | `N-PYF8b-*`, `N-PYF2d-*` |
| python F9, N1 | §8.4 self-tests | `N-PYN1-*`, unit tests |
