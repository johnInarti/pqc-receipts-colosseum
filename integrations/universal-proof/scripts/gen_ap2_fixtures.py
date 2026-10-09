"""Generate AP2 v0.2 fixtures with the OFFICIAL AP2 Python SDK (google-agentic-commerce/AP2).

Produces a real checkout + payment flow, exactly as the official samples do it:
  user (open mandates, SD-JWT) -> shopping agent (closed mandates, KB-SD-JWT) ->
  merchant (signed checkout JWT, ES256 Checkout Receipt) -> merchant payment processor (ES256 Payment Receipt)
and self-verifies both receipts with the SDK's own ReceiptClient.verify_receipt before writing.

Usage (from integrations/universal-proof):
  PYTHONPATH=<AP2 clone>/code/sdk/python <venv-with-ap2-deps>/bin/python scripts/gen_ap2_fixtures.py <AP2 commit>
Keys are freshly generated TEST keys (P-256); only public JWKs are written.
"""
import json
import sys
import time
from pathlib import Path

from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.open_checkout_mandate import OpenCheckoutMandate
from ap2.sdk.generated.open_payment_mandate import AmountRange, OpenPaymentMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.pisp import PISP
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.utils import compute_sha256_b64url
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK


def new_key(kid: str) -> JWK:
    jwk = JWK.from_pyca(ec.generate_private_key(ec.SECP256R1()))
    d = json.loads(jwk.export())
    d["kid"] = kid
    return JWK.from_json(json.dumps(d))


def pub(jwk: JWK) -> dict:
    return json.loads(jwk.export_public())


def main(ap2_commit: str) -> None:
    user, agent, merchant, mpp = new_key("user-key-1"), new_key("agent-key-1"), new_key("merchant-key-1"), new_key("mpp-key-1")
    mc = MandateClient()
    shop = Merchant(id="m-research-api", name="Research API Store", website="https://store.example")

    # Merchant-signed checkout JWT (UCP Checkout object)
    item = LineItem(id="li_report", item=Item(id="sku-report-q3", title="Q3 market report (PDF)", price=1999), quantity=1,
                    totals=[Total(type="subtotal", amount=1999), Total(type="total", amount=1999)])
    checkout = Checkout(id="chk_fx_0001", merchant=shop, line_items=[item], status=Status.ready_for_complete, currency="USD",
                        totals=[Total(type="subtotal", amount=1999), Total(type="total", amount=1999)],
                        links=[Link(type="terms_of_service", url="https://store.example/tos")])
    checkout_jwt = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, json.loads(checkout.model_dump_json(exclude_none=True)), merchant)
    checkout_hash = compute_sha256_b64url(checkout_jwt)

    # Checkout mandate chain: user open mandate -> agent closed mandate
    open_checkout = mc.create(payloads=[OpenCheckoutMandate(constraints=[], cnf={"jwk": pub(agent)})], issuer_key=user)
    checkout_token = mc.present(holder_key=agent, mandate_token=open_checkout,
                                payloads=[CheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash)],
                                aud="merchant", nonce="merchant-nonce-1")
    mc.verify(token=checkout_token, key_or_provider=lambda _t: JWK.from_json(user.export_public()))

    # Payment mandate chain (transaction_id = checkout_hash, as in spec v0.2)
    open_payment = mc.create(payloads=[OpenPaymentMandate(constraints=[AmountRange(currency="USD", max=5000)], cnf={"jwk": pub(agent)})], issuer_key=user)
    pm = PaymentMandate(transaction_id=checkout_hash, payee=shop, payment_amount=Amount(amount=1999, currency="USD"),
                        payment_instrument=PaymentInstrument(id="pi-card-1", type="card"),
                        pisp=PISP(legal_name="Example Processor Ltd.", brand_name="ExamplePay", domain_name="pay.example"))
    payment_token = mc.present(holder_key=agent, mandate_token=open_payment, payloads=[pm], aud="credential-provider", nonce="cp-nonce-1")
    mc.verify(token=payment_token, key_or_provider=lambda _t: JWK.from_json(user.export_public()))

    closed_checkout = mc.get_closed_mandate_jwt(checkout_token)
    closed_payment = mc.get_closed_mandate_jwt(payment_token)

    rc = ReceiptClient()
    checkout_receipt = rc.create_checkout_receipt(merchant=shop.website, reference=compute_sha256_b64url(closed_checkout), order_id="order_fx_0001")
    checkout_receipt_jwt = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, checkout_receipt.model_dump(), merchant)
    payment_receipt = rc.create_payment_receipt(payment_mandate_content=pm, reference=compute_sha256_b64url(closed_payment))
    payment_receipt_jwt = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "mpp-key-1"}, payment_receipt.model_dump(), mpp)
    error_payload = {"status": "Error", "iss": "pay.example", "iat": int(time.time()), "reference": compute_sha256_b64url(closed_payment),
                     "payment_id": "pay_failed", "error": "insufficient_funds", "error_description": "Insufficient funds"}
    payment_receipt_error_jwt = create_jwt({"alg": "ES256", "typ": "JWT", "kid": "mpp-key-1"}, error_payload, mpp)

    # Self-check with the official SDK verifier
    refs = {compute_sha256_b64url(closed_checkout), compute_sha256_b64url(closed_payment)}
    v1 = rc.verify_receipt(payment_receipt_jwt, JWK.from_json(mpp.export_public()), refs.__contains__, True)
    v2 = rc.verify_receipt(checkout_receipt_jwt, JWK.from_json(merchant.export_public()), refs.__contains__, False)
    assert v1 == {"verified": True} and v2 == {"verified": True}, (v1, v2)

    delivered = json.dumps({"report_id": "q3-2026", "title": "Q3 market report", "pages": 42,
                            "pdf_sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"}, sort_keys=True, separators=(",", ":"))
    out = {
        "generator": "integrations/universal-proof/scripts/gen_ap2_fixtures.py",
        "ap2_repo": "https://github.com/google-agentic-commerce/AP2", "ap2_commit": ap2_commit, "ap2_version": "0.2.0",
        "generated_at": int(time.time()),
        "note": "TEST keys generated for this fixture; only public JWKs are stored. Receipts self-verified with ap2.sdk.receipt_wrapper.ReceiptClient.verify_receipt.",
        "sdk_self_check": {"payment_receipt": v1, "checkout_receipt": v2},
        "keys": {"user": pub(user), "agent": pub(agent), "merchant": pub(merchant), "mpp": pub(mpp)},
        "checkout_jwt": checkout_jwt, "checkout_hash": checkout_hash,
        "checkout_mandate_token": checkout_token, "closed_checkout_mandate": closed_checkout,
        "payment_mandate_token": payment_token, "closed_payment_mandate": closed_payment,
        "checkout_receipt_jwt": checkout_receipt_jwt, "payment_receipt_jwt": payment_receipt_jwt,
        "payment_receipt_error_jwt": payment_receipt_error_jwt,
        "delivered": {"media_type": "application/json", "content": delivered},
    }
    dest = Path(__file__).resolve().parent.parent / "fixtures" / "ap2" / "flow-v0.2.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {dest} (receipts verified by the official SDK: {v1}, {v2})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "unknown")
