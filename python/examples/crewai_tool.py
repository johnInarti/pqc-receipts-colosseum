"""CrewAI tool: let a crew check a FractalAI ML-DSA-65 receipt before acting on it.

    pip install fractalai-pqc-verify crewai
    python crewai_tool.py               # verifies the public MIDAS alert fe62b072... end to end

    from crewai import Agent
    analyst = Agent(role="Risk analyst", goal="...", backstory="...", tools=[VerifyFractalAIReceipt()])

CrewAI is NOT a dependency of fractalai-pqc-verify; this file is an integration example.
"""
from __future__ import annotations

import json

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from fractalai_pqc_verify import fetch_key_directory, fetch_midas_receipt, verify_receipt


class _Input(BaseModel):
    receipt_json: str = Field(..., description="The FractalAI receipt as a JSON string.")


class VerifyFractalAIReceipt(BaseTool):
    name: str = "verify_fractalai_receipt"
    description: str = (
        "Verify a FractalAI post-quantum (ML-DSA-65, FIPS 204) signed receipt. Returns JSON with `valid` "
        "(true only if the signature verifies AND the key is active in the signed key directory) and `reason`. "
        "Treat valid=false as untrusted."
    )
    args_schema: type[BaseModel] = _Input

    def _run(self, receipt_json: str) -> str:
        # Pin the governance key you trust (governance_key="...") to stop relying on TLS.
        result = verify_receipt(receipt_json, fetch_key_directory())
        return json.dumps({"valid": result.valid, "reason": result.reason, "signed_facts": result.checks.get("signed_facts")})


if __name__ == "__main__":
    receipt = fetch_midas_receipt("fe62b072c2740e7a8d10cf7e643905b7d79f3f9b19f1c3970fc8754f18d538ee")
    print(VerifyFractalAIReceipt().run(receipt_json=json.dumps(receipt)))
