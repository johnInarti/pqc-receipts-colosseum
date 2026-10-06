import json
from pathlib import Path

import pytest

from fractalai_pqc_verify import mldsa

FIXTURES = Path(__file__).parent / "fixtures"

# Run every signature-dependent test once per installed ML-DSA-65 backend (cross-check implementations).
BACKENDS = mldsa.available_backends()


@pytest.fixture(params=BACKENDS)
def backend(request, monkeypatch):
    monkeypatch.setenv("FRACTALAI_PQC_BACKEND", request.param)
    return request.param


@pytest.fixture
def midas_receipt():
    return json.loads((FIXTURES / "midas-alert-fe62b072.json").read_text("utf-8"))


@pytest.fixture
def directory_json():
    return json.loads((FIXTURES / "x402-receipt-keys-epoch3.json").read_text("utf-8"))
