"""Trust Kernel v2 — Python port of the reference kernel (../../../../kernel, spec/TRUST-KERNEL.md).

    >>> from fractalai_pqc_verify.kernel import verify
    >>> v = verify(receipt_json_text, kind="midas-alert", directory=directory_json_text)
    >>> v["valid"], v["levels"], v["trust_basis"]

Same decision, same reason codes, same baked trust roots as the JavaScript kernel; conformance is the shared
adversarial corpus (``python -m fractalai_pqc_verify.kernel.corpus <corpus-dir>`` must pass 100 %).
"""
from ._codes import DEFAULT_REQUIRE, EXIT, KERNEL_ID, LEVELS, SPEC_VERSION, C, KernelError
from ._hygiene import b64decode_strict, parse_json_strict
from ._model import KINDS, parse_receipt, verify_directory_chain
from ._verify import BAKED_ROOTS, SELF_TEST, verify

__all__ = ["BAKED_ROOTS", "C", "DEFAULT_REQUIRE", "EXIT", "KERNEL_ID", "KINDS", "KernelError", "LEVELS", "SELF_TEST", "SPEC_VERSION",
           "b64decode_strict", "parse_json_strict", "parse_receipt", "verify", "verify_directory_chain"]
