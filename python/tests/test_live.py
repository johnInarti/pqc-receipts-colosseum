"""Live check against the public endpoints (network). Run: pytest -m network"""
import pytest

from fractalai_pqc_verify import fetch_key_directory, fetch_midas_receipt, verify_receipt
from fractalai_pqc_verify.cli import PUBLIC_RECEIPT, main

pytestmark = pytest.mark.network


def test_live_public_midas_receipt_verifies():
    receipt = fetch_midas_receipt(PUBLIC_RECEIPT)
    directory = fetch_key_directory()
    assert directory.trust_basis == "tls" and directory.verification.signature_valid
    r = verify_receipt(receipt, directory)
    assert r.valid, r.reason
    assert directory.status_of(r.public_key) == "active"


def test_live_directory_with_pinned_governance_key():
    first = fetch_key_directory()
    pinned = fetch_key_directory(governance_key=first.governance_key, require_authenticated=True)
    assert pinned.verification.valid and pinned.trust_basis == "pinned-governance-key"


def test_live_cli_exit_code(capsys):
    assert main(["midas"]) == 0
    assert "VALID" in capsys.readouterr().out
