from pathlib import Path

from fractalai_pqc_verify.cli import main

FX = Path(__file__).parent / "fixtures"


def test_cli_conformance(capsys):
    assert main(["conformance"]) == 0
    assert "CONFORMANT — 7/7" in capsys.readouterr().out


def test_cli_receipt_offline(capsys):
    args = ["receipt", str(FX / "midas-alert-fe62b072.json"), "--directory", str(FX / "x402-receipt-keys-epoch3.json")]
    assert main(args) == 0
    assert main(["receipt", str(FX / "midas-alert-fe62b072.json")]) == 1  # no trust anchor -> INVALID
    assert "UNVERIFIED" in capsys.readouterr().out
