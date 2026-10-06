# fractalai-pqc-verify

Offline, **fail-closed** verifier for FractalAI's post-quantum signed receipts — **ML-DSA-65 (FIPS 204, NIST
security category 3)** — for Python agents (LangChain, CrewAI, plain scripts). It is a 1:1 port of the Node
verifier (`verifier/verify-midas-alert.mjs`) and conformance suite (`conformance/`) in this repository, and passes
the same 7 golden vectors.

```bash
# Not on PyPI yet. Until then install from GitHub:
#   pip install "git+https://github.com/johnInarti/pqc-receipts-colosseum.git#subdirectory=python"
pip install fractalai-pqc-verify            # pure Python, no compiler needed
pip install "fractalai-pqc-verify[fast]"    # optional C backend (PQClean via pqcrypto)

fractalai-verify midas                      # fetch + verify the public MIDAS alert fe62b072… end to end
fractalai-verify conformance                # 7 golden vectors → CONFORMANT 7/7
fractalai-verify receipt alert.json --directory saved-keys.json   # fully offline
fractalai-verify directory                  # verify the epoch-chained key directory
```

```python
from fractalai_pqc_verify import fetch_key_directory, verify_receipt

directory = fetch_key_directory()           # checks governance signature, root, kid binding
result = verify_receipt(receipt, directory) # trusted set = keys with status "active"
if result.valid:                            # True ONLY if signature verifies AND key is trusted
    act_on(result.checks["signed_facts"])   # use the SIGNED values, not the unsigned `facts` mirror
else:
    print(result.reason)
```

## What is checked

For a served receipt (`/api/midas/alerts/receipt/<id>`), exactly what the Node reference checks:

1. `receipt_id == sha256(canonical)`;
2. `served_message == "FRACTALAI-x402-served-v1\n<route>\n<receipt_id>"` (domain separation; route
   `midas-alert` by default, so a signature cannot be replayed under another route);
3. the ML-DSA-65 signature over `served_message` verifies with `public_key`;
4. `public_key` is in **your** trusted set — by default the keys with `status: "active"` in the key directory.

Plus one stricter check: the receipt's convenience `facts` object is *not* signed, so if it contradicts the
signed `canonical` text the receipt is rejected.

For the 7 conformance profiles (`x402-served`, `sar`, `acp-verdict`, `jose-ml-dsa-65`, `vc-di-ml-dsa-65`,
`hai-ml-dsa-65`, `a2a-receipt-ml-dsa-65`) `verify_receipt` dispatches on the `profile` field, with RFC 8785 (JCS)
canonicalization byte-compatible with the Node implementation (UTF-16 key order, ECMAScript number formatting,
`JSON.stringify` escaping; fuzzed against Node on 30,000 doubles and 3,000 random strings with 0 mismatches).

**Fail-closed:** a signature that verifies only proves that *some* key signed the bytes. With
`trusted_keys=None` the result is always `valid=False` ("authorship UNVERIFIED"), even for a genuine receipt.

## Trust in the key directory

`fetch_key_directory()` always rejects a tampered directory (ML-DSA-65 governance signature over
`FRACTALAI-key-directory-v1\n<root>`, root recomputed over keys + governance key + `prev_root`, every
`kid == sha256(public_key)[:16]`). A directory that only verifies against its own embedded governance key proves
integrity, not authorship, so without a pin its `trust_basis` is `"tls"`. To remove TLS from the trust path, pin
the governance key after the first run (`governance_key=…`, or `--governance-key`), or compare against an
on-chain anchored root (`anchored_root=…`); `require_authenticated=True` refuses anything else. Save the
directory JSON and use `load_key_directory(path)` to verify with zero network access.

Key lifecycle: `active` keys are trusted; `retiring` keys only with `include_retiring=True` and only for
receipts emitted before `not_after` (`directory.trusted_keys(include_retiring=True, now=receipt["emitted_at"])`);
`reserved` and `revoked` keys never.

## ML-DSA-65 backend — choice and honest security status

| Backend | Install | Notes |
|---|---|---|
| [`dilithium-py`](https://github.com/GiacomoPope/dilithium-py) ≥ 1.4 (default, required) | pure Python, any OS, Python 3.10–3.14 | MIT. Implements FIPS 204 ML-DSA; its author tests it against the NIST known-answer vectors. Its README warns it is not constant-time and not for production *signing*. This package only **verifies** public data with public keys, so timing side channels do not apply. |
| [`pqcrypto`](https://github.com/backbone-hq/pqcrypto) ≥ 1.0 (optional `[fast]`) | prebuilt abi3 wheels | Apache-2.0. CPython bindings to the PQClean C implementation; much faster. Used automatically when installed. |

Select explicitly with `FRACTALAI_PQC_BACKEND=dilithium-py|pqcrypto|auto`. The test suite runs every signature
test against **both** backends, plus the real production receipt signed by the server (`@noble/post-quantum`), so
three independent implementations agree.

**Neither backend is a FIPS 140-3 / CMVP-validated module**, and neither is this package. It implements the
FIPS 204 *algorithm* through open-source libraries. Use it to verify authorship and integrity of receipts; do
not cite it as validated cryptography for compliance purposes.

## Scope (what a valid receipt does and does not mean)

A valid MIDAS alert receipt attests that FractalAI's key signed these facts as observed by its scan at
`observed_at`. It is not a consensus-verified oracle reading, not a liquidation guarantee, not proof of delivery.

## Agent framework examples

`examples/langchain_tool.py` (`langchain-core` `@tool`) and `examples/crewai_tool.py` (`crewai.tools.BaseTool`).
Neither framework is a dependency of this package.

## Development

```bash
cd python
python -m pip install -e ".[test,fast]"
pytest -m "not network"     # offline suite
pytest                      # + live check against https://fractalai.net.co
```

License: Apache-2.0.
