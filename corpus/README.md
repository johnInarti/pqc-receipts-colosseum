# Trust Kernel v2 — adversarial corpus (executable specification)

Every implementation of [`spec/TRUST-KERNEL.md`](../spec/TRUST-KERNEL.md) — the JavaScript kernel, the Python
port, the GitHub Action bundle — MUST pass **100 %** of this corpus. CI refuses anything less.

```bash
node corpus/run.mjs            # JS reference, offline, deterministic
node corpus/run.mjs --live     # + re-verify the live positives (production receipt API + public RPCs)
python -m fractalai_pqc_verify.kernel.corpus corpus   # Python port, same vectors (see python/)
```

## 1. Layout

| Path | What |
|---|---|
| `vectors/P*.json` | positive vectors (real production data first, then synthetic test PKI) |
| `vectors/N-*.json` | negative vectors — one per red-team PoC (ids in `source`) |
| `manifest.json` | `id → sha256(vector file)`; a runner MUST refuse a corpus whose files and manifest disagree, or an empty one |
| `fixtures/` | real data: MIDAS receipt `fe62b072…`, key directory epoch 3, anchor records |
| `fixtures/transcripts/` | **real** JSON-RPC answers (Arc, Arbitrum One, Solana devnet) recorded by `record-live.mjs` |
| `fixtures/stablecoin/` | **real** JSON-RPC answers behind five real COPM / BRLA / MXNB transfers (Polygon, Base, Arbitrum One; two independent RPCs for COPM and MXNB) recorded by `record-stablecoins.mjs` — spec §12 |
| `gen.mjs` | deterministic generator (fixed seeds, deterministic ML-DSA-65 / Ed25519). Expectations are written by hand from the spec — never computed by running the kernel |

## 2. Vector format (`fractalai.trust-corpus/1`)

```jsonc
{
  "id": "N-RTE3-squatted",
  "title": "…", "source": ["redteam-anchor:RT-E3"],
  "input": {
    "receipt": { … }            // a JSON value — runners pass it to the kernel as JSON TEXT
    // or "receipt_text": "…"   // raw bytes (duplicate keys, NaN, BOM, depth, lone surrogates…)
    // "prime_json": ["…"]       // optional: strings the runner parses with the engine's native JSON parser first
  },
  "context": {
    "now": 1791400000,           // verification time (unix seconds)
    "roots": { … },              // optional: test trust roots (an OVERRIDE → trust_basis "override"); absent = baked roots
    "directory": { … },          // key directory (absent = none)
    "directory_history": [ … ],  // intermediate epochs
    "options": {                 // snake_case; see spec §9 for semantics
      "kind": "midas-alert" | "kinds": [ … ], "expected_id": "…", "trusted_keys": [ … ],
      "governance_key": "…", "allow_tls_directory": true, "check_anchors": true, "anchors": [ … ],
      "rpc": { "eip155:5042": ["replay://arc"], "solana:devnet": ["replay://sol-devnet"] },
      "solana_signers": [ … ],
      "check_onchain": true, "token_registry": { … },          // spec §12 (latam-stablecoin-receipt)
      "policy": { "require": [ … ], "allow_testnet_anchors": true, "require_known_anchorer": true,
                  "min_confirmations": 1, "rpc_quorum": 2, "max_clock_skew_sec": 900,
                  "allow_unfinalized_payment": false }
    },
    "rpc_transcript": [ { "url": "replay://arc", "method": "eth_getCode", "params": [ … ], "result": … } ]
  },
  "expect": {
    "valid": false,
    "levels": { "integrity": true, "authentic": true, "trusted": true, "time_anchored": false, "finalized": false },
                                           // "onchain" (spec 2.1): absent = expected null
    "trust_basis": "pinned-root",          // optional
    "exit_code": 13,                       // optional
    "codes": ["ANCHOR_SQUATTED"]           // each MUST appear among the verdict's reason codes
  }
}
```

`{"$ref": "fixtures/<file>.json"}` anywhere means "this fixture's JSON value"; `{"$ref": "fixtures/<file>.json#key"}`
means that fixture's top-level `key`. Inside a list, a `#key` reference whose value is a list is **spliced** (used to
concatenate transcripts).

## 3. RPC replay (normative for runners)

The kernel's JSON-RPC client is given a transport that answers from `rpc_transcript`: a request matches an entry iff
`url`, `method` and `JCS(params)` are equal. An unmatched request is answered with a JSON-RPC error (the kernel then
fails closed). Implementations therefore MUST issue exactly the calls listed in spec §7.2/§7.3 with exactly those
parameters (quantities as lowercase `0x` hex without leading zeros).

## 4. Pass criteria

A vector passes iff `valid` and **all six** levels equal the expectation exactly (`null` = not evaluated; a level absent
from `expect.levels` — e.g. `onchain` in a vector written for spec 2.0 — is expected to be `null`), the optional
`trust_basis` / `exit_code` match, every expected code is present, and an invalid verdict carries at least one reason.

## 5. Provenance

`source` names the PoC each negative vector encodes: `redteam-node:pocN` (verifier/conformance red-team 2026-10-06),
`redteam-anchor:RT-E*/RT-S*` (anchor red-team), `redteam-action:RT-*` (GitHub Action red-team), `redteam-python:F*/N*`
(Python differential red-team). The mapping table is in `spec/TRUST-KERNEL.md` appendix B.
