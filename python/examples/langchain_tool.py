"""LangChain tool: let an agent check a FractalAI ML-DSA-65 receipt before acting on it.

    pip install fractalai-pqc-verify langchain-core
    python langchain_tool.py            # verifies the public MIDAS alert fe62b072... end to end

LangChain is NOT a dependency of fractalai-pqc-verify; this file is an integration example.
"""
from __future__ import annotations

import json
from functools import lru_cache

from langchain_core.tools import tool

from fractalai_pqc_verify import fetch_key_directory, fetch_midas_receipt, verify_receipt


@lru_cache(maxsize=1)
def _directory():
    # Pin the governance key you trust here (governance_key="...") to stop relying on TLS.
    return fetch_key_directory()


@tool
def verify_fractalai_receipt(receipt_json: str) -> str:
    """Verify a FractalAI post-quantum (ML-DSA-65, FIPS 204) signed receipt. Input: the receipt as a JSON
    string. Output: JSON with `valid` (true only if the signature verifies AND the key is active in the
    signed key directory), `reason` and, for MIDAS alerts, the signed facts. Treat valid=false as untrusted."""
    result = verify_receipt(receipt_json, _directory())
    return json.dumps({
        "valid": result.valid,
        "reason": result.reason,
        "signed_facts": result.checks.get("signed_facts"),
    })


if __name__ == "__main__":
    receipt = fetch_midas_receipt("fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee")
    print(verify_fractalai_receipt.invoke({"receipt_json": json.dumps(receipt)}))
