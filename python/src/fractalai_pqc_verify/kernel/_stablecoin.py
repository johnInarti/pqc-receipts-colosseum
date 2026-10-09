"""Kind ``latam-stablecoin-receipt`` and level ``onchain`` — Python mirror of kernel/src/stablecoin.mjs
(spec/TRUST-KERNEL.md §12). Same canonical rules, same registry checks, same JSON-RPC calls with the same
parameters (the corpus replay transcripts are shared), same reason codes."""
from __future__ import annotations

import json
import re
from importlib import resources

from ._anchors import rpc_call
from ._codes import C, KernelError, fail
from ._crypto import ML_DSA_65_PK_BYTES, ML_DSA_65_SIG_BYTES, sha256hex
from ._hygiene import MAX_SAFE, b64decode_strict, is_num, own, to_qty

STABLECOIN_DOMAIN = "FRACTALAI-stablecoin-receipt-v1"
STABLECOIN_CANON_HEADER = "FRACTALAI-stablecoin-transfer-v1"
STABLECOIN_USE = "stablecoin-receipt"
REGISTRY_FORMAT = "fractalai.stablecoin-registry/1"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SEL_SYMBOL = "0x95d89b41"
SEL_DECIMALS = "0x313ce567"
UINT256_MAX = (1 << 256) - 1
ZERO_ADDR = "0x" + "0" * 40

_DEC = r"0|[1-9][0-9]{0,15}"
_ADDR = r"0x[0-9a-f]{40}"
_H32 = r"0x[0-9a-f]{64}"
TRANSFER_FIELDS = [
    ("registry", r"[a-z0-9][a-z0-9.-]{0,63}/[1-9][0-9]{0,5}"),
    ("chain_id", _DEC),
    ("token", _ADDR),
    ("token_symbol", r"[A-Za-z0-9.-]{1,16}"),
    ("token_decimals", r"0|[1-9][0-9]?"),
    ("from", _ADDR),
    ("to", _ADDR),
    ("amount", r"[1-9][0-9]{0,77}"),
    ("amount_decimal", r"(0|[1-9][0-9]{0,77})(\.[0-9]{0,76}[1-9])?"),
    ("tx_hash", _H32),
    ("log_index", _DEC),
    ("block_number", _DEC),
    ("block_hash", _H32),
    ("block_timestamp", _DEC),
    ("confirmations", _DEC),
    ("finality", r"finalized|confirmed"),
    ("issued_at", _DEC),
    ("reference", r"[A-Za-z0-9._:/-]{0,64}"),
]
FIELD_NAMES = [k for k, _ in TRANSFER_FIELDS]
_PATTERNS = {k: re.compile(p) for k, p in TRANSFER_FIELDS}
MAX_CANONICAL = 4096
MARKERS = ["transfer_canonical", "transfer_id", "transfer"]


class _Lookup:
    def __init__(self, reg_id, chains, by_key):
        self.id, self.chains, self._by = reg_id, chains, by_key

    def get(self, chain_id, address):
        return self._by.get(f"{chain_id}:{address}")


def check_registry(reg) -> _Lookup:
    def bad(d):
        fail(C.REGISTRY_INVALID, d)
    if not isinstance(reg, dict):
        bad("registry is not an object")
    if reg.get("format") != REGISTRY_FORMAT:
        bad(f"registry format is not {REGISTRY_FORMAT}")
    if not isinstance(reg.get("id"), str) or not _PATTERNS["registry"].fullmatch(reg["id"]):
        bad("registry id malformed")
    tokens = reg.get("tokens")
    if not isinstance(tokens, list) or not tokens or len(tokens) > 1024:
        bad("registry tokens[] missing, empty or > 1024")
    chains = reg.get("chains") if isinstance(reg.get("chains"), dict) else {}
    by = {}
    for t in tokens:
        if not isinstance(t, dict):
            bad("token entry is not an object")
        cid = t.get("chain_id")
        if not isinstance(cid, int) or isinstance(cid, bool) or cid <= 0 or cid > MAX_SAFE:
            bad("token chain_id is not a positive integer")
        if not isinstance(t.get("address"), str) or not re.fullmatch(_ADDR, t["address"]):
            bad("token address must be lowercase 0x + 40 hex")
        if not isinstance(t.get("symbol"), str) or not _PATTERNS["token_symbol"].fullmatch(t["symbol"]):
            bad(f"token {t['address']} symbol malformed")
        dec = t.get("decimals")
        if not isinstance(dec, int) or isinstance(dec, bool) or dec < 0 or dec > 77:
            bad(f"token {t['address']} decimals out of range")
        k = f"{cid}:{t['address']}"
        if k in by:
            bad(f"token {k} listed twice")
        by[k] = t
    return _Lookup(reg["id"], chains, by)


BAKED_STABLECOIN_REGISTRY = json.loads((resources.files(__package__) / "latam-stablecoins.json").read_text("utf-8"))
_BAKED_LOOKUP = check_registry(BAKED_STABLECOIN_REGISTRY)


def registry_lookup(reg=None) -> _Lookup:
    return _BAKED_LOOKUP if reg is None else check_registry(reg)


def format_units(amount: str, decimals: int) -> str:
    s = str(int(amount))
    if decimals == 0:
        return s
    p = s.rjust(decimals + 1, "0")
    integer, frac = p[: len(p) - decimals], p[len(p) - decimals:].rstrip("0")
    return f"{integer}.{frac}" if frac else integer


def parse_transfer_canonical(canonical) -> dict:
    if not isinstance(canonical, str) or canonical == "" or len(canonical) > MAX_CANONICAL:
        fail(C.CANONICAL_MALFORMED, "transfer_canonical missing or too long")
    lines = canonical.split("\n")
    if lines[0] != STABLECOIN_CANON_HEADER:
        fail(C.CANONICAL_MALFORMED, f"transfer_canonical header is not {STABLECOIN_CANON_HEADER}")
    if len(lines) != len(TRANSFER_FIELDS) + 1:
        fail(C.CANONICAL_MALFORMED, f"transfer_canonical must have exactly {len(TRANSFER_FIELDS)} fields in the normative order")
    out: dict = {}
    for i, (k, _) in enumerate(TRANSFER_FIELDS):
        line = lines[i + 1]
        key, eq, v = line.partition("=")
        if not eq or key != k:
            fail(C.CANONICAL_MALFORMED, f"field {i + 1} must be {k}")
        if not _PATTERNS[k].fullmatch(v):
            fail(C.CANONICAL_MALFORMED, f"{k} value is malformed")
        out[k] = v
    for k in ("chain_id", "log_index", "block_number", "block_timestamp", "confirmations", "issued_at"):
        if int(out[k]) > MAX_SAFE:
            fail(C.CANONICAL_MALFORMED, f"{k} out of range")
    if int(out["amount"]) > UINT256_MAX:
        fail(C.CANONICAL_MALFORMED, "amount exceeds uint256")
    if int(out["chain_id"]) <= 0:
        fail(C.CANONICAL_MALFORMED, "chain_id must be positive")
    if int(out["confirmations"]) < 1:
        fail(C.CANONICAL_MALFORMED, "confirmations must be >= 1")
    if int(out["issued_at"]) < int(out["block_timestamp"]):
        fail(C.CANONICAL_MALFORMED, "issued_at is before the block that carries the transfer")
    return out


def check_transfer_facts(f, lookup):
    if f["registry"] != lookup.id:
        fail(C.TOKEN_NOT_PINNED, f"receipt names registry {f['registry']}, the pinned registry is {lookup.id}")
    t = lookup.get(int(f["chain_id"]), f["token"])
    if not t:
        fail(C.TOKEN_NOT_PINNED, f"token {f['token']} on chain {f['chain_id']} is not in the pinned registry {lookup.id}")
    if t["symbol"] != f["token_symbol"] or str(t["decimals"]) != f["token_decimals"]:
        fail(C.TOKEN_METADATA_MISMATCH, f"signed {f['token_symbol']}/{f['token_decimals']} != pinned {t['symbol']}/{t['decimals']}")
    if format_units(f["amount"], t["decimals"]) != f["amount_decimal"]:
        fail(C.AMOUNT_FORMAT_MISMATCH, f"amount_decimal {f['amount_decimal']} != amount {f['amount']} at {t['decimals']} decimals")
    if f["from"] == ZERO_ADDR or f["to"] == ZERO_ADDR:
        fail(C.PAYMENT_NOT_A_TRANSFER, "mint/burn (zero address) is not a payment between two parties")
    return t


def parse_stablecoin_receipt(r, ctx=None):
    ctx = ctx or {}
    known = {"profile", "algorithm", "domain", "transfer_canonical", "transfer_id", "signed_message", "transfer", "issued_at", "public_key", "signature"}
    if own(r, "algorithm") and r["algorithm"] != "ml-dsa-65":
        fail(C.ALGORITHM, f"algorithm {r['algorithm']!r} is not ml-dsa-65")
    lookup = registry_lookup(ctx.get("token_registry"))
    fields = parse_transfer_canonical(r.get("transfer_canonical"))
    tid = sha256hex(r["transfer_canonical"])
    message = f"{STABLECOIN_DOMAIN}\n{tid}"
    if own(r, "domain") and r["domain"] != STABLECOIN_DOMAIN:
        fail(C.DOMAIN_MISMATCH, f"domain is not {STABLECOIN_DOMAIN}")
    if own(r, "transfer_id") and r["transfer_id"] != tid:
        fail(C.RECEIPT_ID_MISMATCH, "transfer_id != sha256(transfer_canonical)")
    if own(r, "signed_message") and r["signed_message"] != message:
        fail(C.SIGNED_MESSAGE_MISMATCH, "signed_message != reconstructed signed message")
    signed_time = int(fields["issued_at"])
    if own(r, "issued_at") and not (is_num(r["issued_at"]) and r["issued_at"] == signed_time):
        fail(C.UNSIGNED_FIELD_MISMATCH, f"top-level issued_at {r['issued_at']!r} != signed issued_at {signed_time}")
    if own(r, "transfer"):
        tr = r["transfer"]
        if not isinstance(tr, dict):
            fail(C.UNSIGNED_FIELD_MISMATCH, "transfer is not an object")
        bad = [k for k in tr if k not in fields or not isinstance(tr[k], str) or tr[k] != fields[k]]
        bad += [k for k in FIELD_NAMES if k not in tr]
        if bad:
            fail(C.UNSIGNED_FIELD_MISMATCH, "transfer differs from the signed canonical: " + ", ".join(dict.fromkeys(bad)))
    check_transfer_facts(fields, lookup)
    return {
        "kind": "latam-stablecoin-receipt", "content_id": tid, "message": message,
        "pk": b64decode_strict(r.get("public_key"), ML_DSA_65_PK_BYTES, "public_key"),
        "sig": b64decode_strict(r.get("signature"), ML_DSA_65_SIG_BYTES, "signature"),
        "public_key_b64": r.get("public_key"), "signed_time": signed_time,
        "signed": {"transfer_id": tid, "canonical_header": STABLECOIN_CANON_HEADER, **fields},
        "ignored": [k for k in r if k not in known and k not in ("anchor", "anchors")],
    }


# ── on-chain observation (spec §12.4) ──
def _lc(s):
    return str(s).lower()


def _malformed(d):
    return KernelError(C.PAYMENT_RPC_MALFORMED, d)


def _pqty(h, what):
    if not isinstance(h, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", h):
        raise _malformed(f"{what} is not a hex quantity")
    v = int(h[2:], 16)
    if v > MAX_SAFE:
        raise _malformed(f"{what} out of range")
    return v


def _is_h32(s):
    return isinstance(s, str) and re.fullmatch(r"0x[0-9a-fA-F]{64}", s) is not None


def abi_decode_string(h) -> str:
    if not isinstance(h, str) or not re.fullmatch(r"0x([0-9a-fA-F]{64})+", h):
        fail(C.PAYMENT_TOKEN_METADATA, "symbol() did not return ABI words")
    d = h[2:].lower()
    if int(d[0:64], 16) != 32:
        fail(C.PAYMENT_TOKEN_METADATA, "symbol() is not an ABI dynamic string")
    n = int(d[64:128], 16)
    if n > 64:
        fail(C.PAYMENT_TOKEN_METADATA, "symbol() string too long")
    words = -(-n // 32)
    if len(d) != 128 + words * 64:
        fail(C.PAYMENT_TOKEN_METADATA, "symbol() return has trailing or missing words")
    if d[128 + n * 2:].strip("0"):
        fail(C.PAYMENT_TOKEN_METADATA, "symbol() padding is not zero")
    try:
        return bytes.fromhex(d[128:128 + n * 2]).decode("utf-8")
    except UnicodeDecodeError:
        fail(C.PAYMENT_TOKEN_METADATA, "symbol() is not UTF-8")


def abi_decode_uint8(h) -> int:
    if not isinstance(h, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", h):
        fail(C.PAYMENT_TOKEN_METADATA, "decimals() did not return one ABI word")
    v = int(h[2:], 16)
    if v > 255:
        fail(C.PAYMENT_TOKEN_METADATA, "decimals() out of uint8 range")
    return v


def observe_transfer(url, q, transport) -> dict:
    call = lambda m, p: rpc_call(url, m, p, transport)  # noqa: E731
    chain_id, tx, li = q["chain_id"], q["tx_hash"], q["log_index"]
    live = _pqty(call("eth_chainId", []), "eth_chainId")
    if live != chain_id:
        fail(C.PAYMENT_WRONG_CHAIN, f"RPC serves chain {live}, the payment is on chain {chain_id}")
    rc = call("eth_getTransactionReceipt", [tx])
    if rc is None:
        fail(C.PAYMENT_TX_NOT_FOUND, f"transaction {tx} not found on chain {chain_id}")
    if not isinstance(rc, dict):
        raise _malformed("transaction receipt is not an object")
    if rc.get("status") != "0x1":
        if rc.get("status") == "0x0":
            fail(C.PAYMENT_TX_REVERTED, "the transaction reverted (status 0x0): no transfer happened")
        raise _malformed("receipt status is neither 0x1 nor 0x0")
    if _lc(rc.get("transactionHash")) != tx:
        raise _malformed("receipt transactionHash differs from the requested one")
    if not _is_h32(rc.get("blockHash")):
        raise _malformed("receipt has no blockHash")
    bn = _pqty(rc.get("blockNumber"), "receipt.blockNumber")
    bh = _lc(rc["blockHash"])
    logs = rc.get("logs") if isinstance(rc.get("logs"), list) else []
    at = [lg for lg in logs if isinstance(lg, dict) and _pqty(lg.get("logIndex"), "log.logIndex") == li]
    if not at:
        fail(C.PAYMENT_LOG_NOT_FOUND, f"transaction has no log with index {li}")
    if len(at) > 1:
        raise _malformed(f"several logs carry index {li}")
    log = at[0]
    if log.get("removed") is True:
        fail(C.PAYMENT_LOG_REMOVED, "the log was removed by a reorg")
    if _lc(log.get("blockHash")) != bh or _pqty(log.get("blockNumber"), "log.blockNumber") != bn or _lc(log.get("transactionHash")) != tx:
        raise _malformed("log block/tx fields disagree with the receipt")
    if not isinstance(log.get("address"), str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", log["address"]):
        raise _malformed("log address malformed")
    emitter = _lc(log["address"])
    if q.get("token") is not None and emitter != q["token"]:
        fail(C.PAYMENT_LOG_WRONG_CONTRACT, f"log {li} was emitted by {emitter}, not by the token {q['token']}")
    if q.get("token") is None and not q["lookup"].get(chain_id, emitter):
        fail(C.TOKEN_NOT_PINNED, f"log {li} was emitted by {emitter}, which is not a pinned token on chain {chain_id}")
    tp = log.get("topics")
    if (not isinstance(tp, list) or len(tp) != 3 or _lc(tp[0]) != TRANSFER_TOPIC
            or not all(isinstance(t, str) and re.fullmatch(r"0x0{24}[0-9a-fA-F]{40}", t) for t in tp[1:])):
        fail(C.PAYMENT_LOG_NOT_TRANSFER, "log is not an ERC-20 Transfer(address,address,uint256) event")
    data = log.get("data")
    if not isinstance(data, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", data):
        fail(C.PAYMENT_LOG_NOT_TRANSFER, "Transfer data is not exactly one uint256")
    frm, to, amount = "0x" + _lc(tp[1])[26:], "0x" + _lc(tp[2])[26:], str(int(data[2:], 16))
    blk = call("eth_getBlockByNumber", [to_qty(bn), False])
    if not isinstance(blk, dict):
        fail(C.PAYMENT_REORGED, f"block {bn} not found")
    if _pqty(blk.get("number"), "block.number") != bn:
        raise _malformed("header number mismatch")
    if _lc(blk.get("hash")) != bh:
        fail(C.PAYMENT_REORGED, f"the receipt's block {bh} is not the canonical block {_lc(blk.get('hash'))} at height {bn}")
    t = _pqty(blk.get("timestamp"), "block.timestamp")
    symbol = abi_decode_string(call("eth_call", [{"to": emitter, "data": SEL_SYMBOL}, "latest"]))
    decimals = abi_decode_uint8(call("eth_call", [{"to": emitter, "data": SEL_DECIMALS}, "latest"]))
    head = _pqty(call("eth_blockNumber", []), "eth_blockNumber")
    finalized = False
    try:
        f = call("eth_getBlockByNumber", ["finalized", False])
        finalized = isinstance(f, dict) and _pqty(f.get("number"), "finalized.number") >= bn
    except KernelError:
        finalized = False
    return {"chain_id": chain_id, "token": emitter, "from": frm, "to": to, "amount": amount, "tx_hash": tx, "log_index": li,
            "block_number": bn, "block_hash": bh, "block_timestamp": t, "symbol": symbol, "decimals": decimals,
            "head": head, "confirmations": head - bn + 1, "finalized": finalized}


AGREEMENT_FIELDS = ["chain_id", "token", "from", "to", "amount", "tx_hash", "log_index", "block_number", "block_hash", "block_timestamp", "symbol", "decimals"]


def observe_everywhere(urls, q, policy, transport) -> dict:
    if not urls:
        fail(C.PAYMENT_NO_RPC, f"no RPC configured for chain {q['chain_id']}")
    if len(urls) < policy["rpc_quorum"]:
        fail(C.RPC_QUORUM, f"policy requires {policy['rpc_quorum']} independent RPCs, {len(urls)} configured")
    results = []
    for url in urls:
        try:
            results.append(observe_transfer(url, q, transport))
        except KernelError as e:
            e.detail = f"{e.detail} [rpc {len(results) + 1}/{len(urls)}]"
            raise
        except Exception as e:  # noqa: BLE001
            raise KernelError(C.RPC_ERROR, str(e)) from None
    for r in results[1:]:
        if any(json.dumps(results[0][f]) != json.dumps(r[f]) for f in AGREEMENT_FIELDS):
            fail(C.RPC_DISAGREEMENT, "independent RPCs disagree on the transfer facts")
    return {**results[0], "confirmations": min(r["confirmations"] for r in results), "finalized": all(r["finalized"] for r in results), "rpc_count": len(results)}


def verify_stablecoin_payment(s, ctx) -> dict:
    lookup = ctx["lookup"]
    urls = ctx.get("rpc_urls") or ([lookup.chains[s["chain_id"]]["default_rpc"]] if isinstance(lookup.chains.get(s["chain_id"]), dict) and lookup.chains[s["chain_id"]].get("default_rpc") else [])
    pol = ctx["policy"]
    o = observe_everywhere(urls, {"chain_id": int(s["chain_id"]), "tx_hash": s["tx_hash"], "log_index": int(s["log_index"]), "token": s["token"]}, pol, ctx["transport"])
    if o["block_number"] != int(s["block_number"]):
        fail(C.PAYMENT_BLOCK_MISMATCH, f"the transaction is in block {o['block_number']}, the receipt says {s['block_number']}")
    if o["block_hash"] != s["block_hash"]:
        fail(C.PAYMENT_REORGED, f"signed block_hash {s['block_hash']} is no longer the canonical block of this transaction ({o['block_hash']})")
    if o["block_timestamp"] != int(s["block_timestamp"]):
        fail(C.PAYMENT_TIME_MISMATCH, f"header timestamp {o['block_timestamp']} != signed block_timestamp {s['block_timestamp']}")
    if o["from"] != s["from"] or o["to"] != s["to"]:
        fail(C.PAYMENT_PARTY_MISMATCH, f"on-chain {o['from']} -> {o['to']} differs from the signed parties")
    if o["amount"] != s["amount"]:
        fail(C.PAYMENT_AMOUNT_MISMATCH, f"on-chain amount {o['amount']} != signed amount {s['amount']}")
    if o["symbol"] != s["token_symbol"] or str(o["decimals"]) != s["token_decimals"]:
        fail(C.PAYMENT_TOKEN_METADATA, f"token now reports {o['symbol']}/{o['decimals']}, signed {s['token_symbol']}/{s['token_decimals']}")
    need = max(1, pol["min_confirmations"])
    if o["confirmations"] < need:
        fail(C.PAYMENT_CONFIRMATIONS, f"{o['confirmations']} confirmations < policy {need}")
    if o["confirmations"] < int(s["confirmations"]):
        fail(C.PAYMENT_CONFIRMATIONS, f"chain shows {o['confirmations']} confirmations, fewer than the {s['confirmations']} the signer claimed")
    if s["finality"] == "finalized" and not o["finalized"]:
        fail(C.PAYMENT_NOT_FINALIZED, "the signer claimed finality but the chain does not report the block as finalized")
    if not o["finalized"] and not pol["allow_unfinalized_payment"]:
        fail(C.PAYMENT_NOT_FINALIZED, "the payment block is not finalized yet (policy.allowUnfinalizedPayment is false)")
    return o
