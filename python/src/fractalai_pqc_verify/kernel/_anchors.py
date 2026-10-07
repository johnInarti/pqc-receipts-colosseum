"""Consensus time proofs — Python mirror of kernel/src/{rpc,anchors/evm,anchors/solana-wire,anchors/solana}.mjs
(spec/TRUST-KERNEL.md §7). Issues exactly the same JSON-RPC calls with exactly the same parameters as the JS
reference, so the corpus replay transcripts are shared."""
from __future__ import annotations

import json
import re

from ._codes import C, KernelError, fail
from ._crypto import ed25519_verify, keccak256hex, sha256hex
from ._hygiene import b64decode_strict, bounded_fetch, is_hex0x, is_safe_int, one_line, parse_json_strict, qty, to_qty

RECEIPT_ANCHORED_TOPIC = "0x86069938b925599e2755e87e9b3242e8f6cbd24f2bc3d1ab52bc585d82646184"
ANCHOR_SCHEME = "fractalai.pqc-receipt-anchor/1"
MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
_seq = [0]


def default_transport(url: str, body: str) -> str:
    return bounded_fetch(url, data=body.encode("utf-8"))


def rpc_call(url, method, params, transport):
    _seq[0] += 1
    body = json.dumps({"jsonrpc": "2.0", "id": _seq[0], "method": method, "params": params}, separators=(",", ":"))
    try:
        text = transport(url, body)
    except KernelError:
        raise
    except Exception as e:  # noqa: BLE001
        raise KernelError(C.RPC_ERROR, f"{method}: {one_line(e, 160)}") from None
    try:
        j = parse_json_strict(text)
    except KernelError as e:
        raise KernelError(C.RPC_ERROR, f"{method}: unparsable response ({e.code})") from None
    if not isinstance(j, dict):
        raise KernelError(C.RPC_ERROR, f"{method}: response is not an object")
    if j.get("error") is not None:
        err = j["error"]
        raise KernelError(C.RPC_ERROR, f"{method}: {one_line(err.get('message') if isinstance(err, dict) else err, 160)}")
    if "result" not in j:
        raise KernelError(C.RPC_ERROR, f"{method}: no result")
    return j["result"]


def _same(a, b, fields):
    return all(json.dumps(a.get(f), sort_keys=True) == json.dumps(b.get(f), sort_keys=True) for f in fields)


def _lc(s):
    return str(s).lower()


# ── EVM ──
def _evm_once(url, chain_id, dep, ids, signed_time, ref, policy, transport):
    call = lambda m, p: rpc_call(url, m, p, transport)  # noqa: E731
    live = qty(call("eth_chainId", []), "eth_chainId")
    if live != chain_id:
        fail(C.ANCHOR_WRONG_CHAIN, f"RPC serves chain {live}, not {chain_id}")
    code = call("eth_getCode", [dep["contract"], "latest"])
    if not isinstance(code, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", code) or len(code) % 2:
        fail(C.ANCHOR_CODEHASH_MISMATCH, f"no contract code at {dep['contract']}")
    ch = keccak256hex(bytes.fromhex(code[2:]))
    if ch != dep["runtime_codehash"]:
        fail(C.ANCHOR_CODEHASH_MISMATCH, f"runtime code hash {ch} != pinned {dep['runtime_codehash']}")
    rid = "0x" + ids["receipt_id"]
    match = lambda l: isinstance(l, dict) and _lc(l.get("address")) == dep["contract"] and isinstance(l.get("topics"), list) and len(l["topics"]) >= 2 and _lc(l["topics"][0]) == RECEIPT_ANCHORED_TOPIC and _lc(l["topics"][1]) == rid  # noqa: E731,E741
    if "tx_hash" in ref:
        if not is_hex0x(ref["tx_hash"], 64):
            fail(C.ANCHOR_REF_MALFORMED, "tx_hash is not 0x + 64 hex")
        rc = call("eth_getTransactionReceipt", [ref["tx_hash"]])
        if not isinstance(rc, dict):
            fail(C.ANCHOR_NOT_FOUND, "transaction receipt not found")
        if rc.get("status") != "0x1":
            fail(C.ANCHOR_TX_FAILED, "anchor transaction did not succeed")
        cands = [l for l in (rc.get("logs") if isinstance(rc.get("logs"), list) else []) if match(l)]  # noqa: E741
        pick = [l for l in cands if qty(l.get("logIndex"), "logIndex") == ref["log_index"]] if "log_index" in ref else cands  # noqa: E741
        if not pick:
            fail(C.ANCHOR_NOT_FOUND, "no ReceiptAnchored(receiptId) log from the pinned contract in that transaction")
        if len(pick) > 1:
            fail(C.ANCHOR_AMBIGUOUS, "more than one matching log")
        log = pick[0]
        if _lc(log.get("transactionHash", ref["tx_hash"])) != _lc(ref["tx_hash"]):
            fail(C.ANCHOR_LOG_MALFORMED, "log transactionHash differs from the requested one")
    else:
        frm = ref["block_number"] if "block_number" in ref else dep["from_block"]
        to = to_qty(ref["block_number"]) if "block_number" in ref else "latest"
        logs = call("eth_getLogs", [{"address": dep["contract"], "topics": [RECEIPT_ANCHORED_TOPIC, rid], "fromBlock": to_qty(frm), "toBlock": to}])
        if not isinstance(logs, list):
            fail(C.RPC_ERROR, "eth_getLogs did not return an array")
        cands = [l for l in logs if match(l)]  # noqa: E741
        if not cands:
            fail(C.ANCHOR_NOT_FOUND, "no ReceiptAnchored(receiptId) event on the pinned contract")
        if len(cands) > 1:
            fail(C.ANCHOR_AMBIGUOUS, "several ReceiptAnchored events for one receiptId")
        log = cands[0]
    if log.get("removed") is True:
        fail(C.ANCHOR_LOG_REMOVED, "log was removed by a reorg")
    data = log.get("data")
    if len(log["topics"]) != 4 or not isinstance(data, str) or not re.fullmatch(r"0x[0-9a-fA-F]{192}", data):
        fail(C.ANCHOR_LOG_MALFORMED, "event does not have 4 topics and 96 bytes of data")
    if not is_hex0x(log.get("blockHash"), 64):
        fail(C.ANCHOR_LOG_MALFORMED, "log has no blockHash")
    bn = qty(log.get("blockNumber"), "log.blockNumber")
    if "block_number" in ref and ref["block_number"] != bn:
        fail(C.ANCHOR_BLOCK_MISMATCH, f"reference says block {ref['block_number']}, log is in {bn}")
    d = data[2:]
    if not (d[0:48] == "0" * 48 and d[64:88] == "0" * 24 and d[128:176] == "0" * 48):
        fail(C.ANCHOR_LOG_MALFORMED, "event data has non-canonical padding")
    observed_at = int(d[0:64], 16)
    anchored_by = "0x" + d[88:128].lower()
    event_at = int(d[128:192], 16)
    if _lc(log["topics"][2]) != "0x" + ids["payload_hash"]:
        fail(C.ANCHOR_SQUATTED, f"receiptId occupied by {anchored_by} with a different payloadHash (write-once slot squatted)")
    if _lc(log["topics"][3]) != "0x" + ids["kid16"] + "0" * 48:
        fail(C.ANCHOR_KID_MISMATCH, f"receiptId anchored by {anchored_by} under another key id")
    blk = call("eth_getBlockByNumber", [to_qty(bn), False])
    if not isinstance(blk, dict):
        fail(C.ANCHOR_BLOCK_MISMATCH, f"block {bn} not found")
    if _lc(blk.get("hash")) != _lc(log["blockHash"]):
        fail(C.ANCHOR_BLOCK_MISMATCH, f"log blockHash is not the canonical hash of block {bn}")
    if qty(blk.get("number"), "block.number") != bn:
        fail(C.ANCHOR_BLOCK_MISMATCH, "header number mismatch")
    t = qty(blk.get("timestamp"), "block.timestamp")
    if event_at != t:
        fail(C.ANCHOR_TIME_MISMATCH, f"event anchoredAt {event_at} != header timestamp {t}")
    if observed_at != signed_time:
        fail(C.ANCHOR_OBSERVED_AT_MISMATCH, f"on-chain observedAt {observed_at} != signed time {signed_time}")
    if signed_time > t + policy["skew"]:
        fail(C.ANCHOR_FORWARD_DATED, f"signed time {signed_time} is after the anchor block time {t}")
    head = qty(call("eth_blockNumber", []), "eth_blockNumber")
    if head - bn + 1 < policy["min_confirmations"]:
        fail(C.ANCHOR_CONFIRMATIONS, f"{head - bn + 1} confirmations < {policy['min_confirmations']}")
    finalized = False
    try:
        f = call("eth_getBlockByNumber", ["finalized", False])
        finalized = isinstance(f, dict) and qty(f.get("number"), "finalized.number") >= bn
    except KernelError:
        finalized = False
    return {"chain": f"eip155:{chain_id}", "contract": dep["contract"], "tx_hash": _lc(log.get("transactionHash", ref.get("tx_hash", ""))),
            "log_index": qty(log.get("logIndex"), "logIndex"), "block_number": bn, "block_hash": _lc(log["blockHash"]), "time": t,
            "observed_at": observed_at, "anchored_by": anchored_by, "finalized": finalized}


def verify_evm_anchor(ref, ctx):
    chain_id = ref.get("chain_id")
    if not (is_safe_int(chain_id) and chain_id > 0):
        fail(C.ANCHOR_REF_MALFORMED, "chain_id is not a positive integer")
    chain_id = int(chain_id)
    dep = ((ctx["roots"].get("anchors") or {}).get("evm") or {}).get(str(chain_id))
    if not dep:
        fail(C.ANCHOR_CHAIN_NOT_PINNED, f"no pinned PQCReceiptAnchor deployment for chain {chain_id}")
    if "contract" in ref and _lc(ref["contract"]) != dep["contract"]:
        fail(C.ANCHOR_CONTRACT_NOT_PINNED, f"reference names contract {_lc(ref['contract'])}, pinned is {dep['contract']}")
    for f in ("block_number", "log_index"):
        if f in ref and not (is_safe_int(ref[f]) and ref[f] >= 0):
            fail(C.ANCHOR_REF_MALFORMED, f"{f} must be a non-negative integer")
    if ctx["signed_time"] is None:
        fail(C.ANCHOR_REQUIRES_SIGNED_TIME, "this kind signs no time")
    urls = ctx.get("rpc_urls") or ([dep["default_rpc"]] if dep.get("default_rpc") else [])
    if not urls:
        fail(C.ANCHOR_NO_RPC, f"no RPC configured for chain {chain_id}")
    if len(urls) < ctx["policy"]["rpc_quorum"]:
        fail(C.RPC_QUORUM, f"policy requires {ctx['policy']['rpc_quorum']} independent RPCs, {len(urls)} configured")
    results = []
    for u in urls:
        try:
            results.append(_evm_once(u, chain_id, dep, ctx["ids"], ctx["signed_time"], ref, ctx["policy"], ctx["transport"]))
        except KernelError as e:
            raise KernelError(e.code, f"{e.detail} [rpc {len(results) + 1}/{len(urls)}]") from None
    for r in results[1:]:
        if not _same(results[0], r, ["block_number", "block_hash", "time", "observed_at", "anchored_by", "tx_hash", "log_index"]):
            fail(C.RPC_DISAGREEMENT, "independent RPCs disagree on the anchor facts")
    facts = {**results[0], "finalized": all(r["finalized"] for r in results), "rpc_count": len(results), "network_class": dep["network_class"]}
    facts["anchorer_known"] = facts["anchored_by"] in ((ctx["roots"].get("known_anchorers") or {}).get("evm") or [])
    return facts


# ── Solana wire ──
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    for x in b:
        if x:
            break
        s = "1" + s
    return s


def b58decode(s, expected_len=None) -> bytes:
    if not isinstance(s, str) or not s or len(s) > 128 or not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", s):
        fail(C.INPUT_SHAPE, "invalid base58")
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    out = b"\x00" * (len(s) - len(s.lstrip("1"))) + out
    if expected_len is not None and len(out) != expected_len:
        fail(C.INPUT_SHAPE, f"base58 value is {len(out)} bytes, expected {expected_len}")
    if b58encode(out) != s:
        fail(C.INPUT_SHAPE, "non-canonical base58")
    return out


def build_memo(ids, observed_at) -> str:
    return f"{ANCHOR_SCHEME}|rid={ids['receipt_id']}|ph={ids['payload_hash']}|kid={ids['kid16']}|obs={observed_at}"


def parse_transaction(wire: bytes) -> dict:
    buf = bytes(wire)
    i = [0]

    def bad(m):
        fail(C.SOL_TX_MALFORMED, m)

    def take(n):
        if n < 0 or i[0] + n > len(buf):
            bad("truncated transaction")
        v = buf[i[0]:i[0] + n]
        i[0] += n
        return v

    def byte():
        return take(1)[0]

    def sv():
        n = 0
        for k in range(3):
            b = byte()
            n |= (b & 0x7F) << (7 * k)
            if not b & 0x80:
                if k > 0 and b == 0:
                    bad("non-minimal shortvec")
                return n
        bad("shortvec too long")

    nsig = sv()
    if nsig == 0 or nsig > 16:
        bad("bad signature count")
    sigs = [take(64) for _ in range(nsig)]
    msg_start = i[0]
    version = "legacy"
    if i[0] < len(buf) and buf[i[0]] & 0x80:
        version = byte() & 0x7F
        if version != 0:
            bad(f"unsupported transaction version {version}")
    header = (byte(), byte(), byte())
    nkeys = sv()
    if nkeys == 0 or nkeys > 64:
        bad("bad account key count")
    keys = [take(32) for _ in range(nkeys)]
    take(32)  # recent blockhash
    ixs = []
    for _ in range(sv()):
        prog = byte()
        accts = list(take(sv()))
        data = take(sv())
        if prog >= len(keys) or any(a >= len(keys) for a in accts):
            bad("instruction references an account outside the static keys")
        ixs.append({"prog": prog, "accounts": accts, "data": data})
    lookups = 0
    if version != "legacy":
        lookups = sv()
        for _ in range(lookups):
            take(32)
            take(sv())
            take(sv())
    if i[0] != len(buf):
        bad("trailing bytes after message")
    if len(sigs) != header[0]:
        bad("signature count != header.numRequiredSignatures")
    if header[0] > len(keys):
        bad("more signers than keys")
    return {"signatures": sigs, "message": buf[msg_start:], "keys": keys, "instructions": ixs, "lookups": lookups}


def _sol_once(url, cluster, sig, sig_bytes, signers, memo, signed_time, policy, transport):
    call = lambda m, p: rpc_call(url, m, p, transport)  # noqa: E731
    g = call("getGenesisHash", [])
    if g != cluster["genesis_hash"]:
        fail(C.SOL_GENESIS_MISMATCH, f"RPC genesis {str(g)[:44]} is not the pinned {cluster['name']} genesis")
    tx = call("getTransaction", [sig, {"encoding": "base64", "commitment": "finalized", "maxSupportedTransactionVersion": 0}])
    if not isinstance(tx, dict):
        fail(C.ANCHOR_NOT_FOUND, "transaction not found at finalized commitment")
    meta = tx.get("meta")
    if not isinstance(meta, dict) or "err" not in meta or meta["err"] is not None:
        fail(C.ANCHOR_TX_FAILED, "transaction failed or has no meta")
    if not (is_safe_int(tx.get("slot")) and tx["slot"] >= 0):
        fail(C.SOL_TX_MALFORMED, "slot missing")
    if not (is_safe_int(tx.get("blockTime")) and tx["blockTime"] > 0):
        fail(C.SOL_NO_BLOCKTIME, "finalized transaction has no blockTime — no time proof")
    st = call("getSignatureStatuses", [[sig], {"searchTransactionHistory": True}])
    s0 = st["value"][0] if isinstance(st, dict) and isinstance(st.get("value"), list) and st["value"] else None
    if not isinstance(s0, dict) or s0.get("confirmationStatus") != "finalized" or "err" not in s0 or s0["err"] is not None:
        fail(C.SOL_NOT_FINALIZED, "signature status is not finalized/ok")
    if not (isinstance(s0.get("slot"), (int, float)) and not isinstance(s0.get("slot"), bool) and s0["slot"] == tx["slot"]):
        fail(C.SOL_STATUS_SLOT, f"status slot {s0.get('slot')} != transaction slot {tx['slot']}")
    t = tx.get("transaction")
    if not (isinstance(t, list) and len(t) == 2 and t[1] == "base64" and isinstance(t[0], str)):
        fail(C.SOL_TX_MALFORMED, 'transaction not returned as [base64, "base64"]')
    wire = b64decode_strict(t[0], None, "transaction")
    p = parse_transaction(wire)
    if len(p["signatures"]) != 1:
        fail(C.SOL_SIGNER_COUNT, f"anchor tx must have exactly one signer, has {len(p['signatures'])}")
    if p["signatures"][0] != sig_bytes:
        fail(C.SOL_SIGNATURE_MISMATCH, "RPC returned a transaction whose signature is not the requested one")
    if p["lookups"]:
        fail(C.SOL_LOOKUP_TABLES, "address lookup tables are not accepted in an anchor tx")
    signer = b58encode(p["keys"][0])
    if not ed25519_verify(p["signatures"][0], p["message"], p["keys"][0]):
        fail(C.SOL_ED25519_INVALID, "Ed25519 signature over the message does not verify")
    if signer not in signers:
        fail(C.SOL_SIGNER_NOT_ANNOUNCED, f"signer {signer} is not an announced anchor key for {cluster['name']}")
    if len(p["instructions"]) != 1:
        fail(C.SOL_INSTRUCTION_COUNT, f"anchor tx must carry exactly 1 instruction, has {len(p['instructions'])}")
    ix = p["instructions"][0]
    if b58encode(p["keys"][ix["prog"]]) != MEMO_PROGRAM_ID:
        fail(C.SOL_NOT_MEMO, "the instruction is not SPL Memo v2")
    if 0 not in ix["accounts"]:
        fail(C.SOL_MEMO_SIGNER, "memo instruction does not list the signer")
    if ix["data"] != memo.encode("utf-8"):
        fail(C.SOL_MEMO_MISMATCH, "on-chain memo is not byte-identical to the memo rebuilt from the signed receipt")
    if signed_time > tx["blockTime"] + policy["skew"]:
        fail(C.ANCHOR_FORWARD_DATED, f"signed time {signed_time} after blockTime {tx['blockTime']}")
    return {"slot": int(tx["slot"]), "time": int(tx["blockTime"]), "signer": signer, "wire_sha256": sha256hex(wire), "finalized": True}


def verify_solana_anchor(ref, ctx):
    clusters = ((ctx["roots"].get("anchors") or {}).get("solana") or {}).get("clusters") or {}
    name = ref.get("cluster")
    if not isinstance(name, str) or name not in clusters:
        fail(C.ANCHOR_CHAIN_NOT_PINNED, f"Solana cluster {name!r} is not pinned")
    cluster = {"name": name, **clusters[name]}
    sig_bytes = b58decode(ref.get("signature"), 64)
    signers = ctx.get("solana_signers")
    if signers is None:
        signers = ((ctx["roots"]["anchors"]["solana"].get("announced_signers") or {}).get(name)) or []
    if "signer" in ref and ref["signer"] not in signers:
        fail(C.SOL_SIGNER_NOT_ANNOUNCED, f"reference names signer {str(ref['signer'])[:44]}, not announced for {name}")
    if ctx["signed_time"] is None:
        fail(C.ANCHOR_REQUIRES_SIGNED_TIME, "this kind signs no time")
    memo = build_memo(ctx["ids"], ctx["signed_time"])
    urls = ctx.get("rpc_urls") or ([cluster["default_rpc"]] if cluster.get("default_rpc") else [])
    if not urls:
        fail(C.ANCHOR_NO_RPC, f"no RPC configured for Solana {name}")
    if len(urls) < ctx["policy"]["rpc_quorum"]:
        fail(C.RPC_QUORUM, f"policy requires {ctx['policy']['rpc_quorum']} independent RPCs, {len(urls)} configured")
    results = []
    for u in urls:
        try:
            results.append(_sol_once(u, cluster, ref["signature"], sig_bytes, signers, memo, ctx["signed_time"], ctx["policy"], ctx["transport"]))
        except KernelError as e:
            raise KernelError(e.code, f"{e.detail} [rpc {len(results) + 1}/{len(urls)}]") from None
    for r in results[1:]:
        if not _same(results[0], r, ["slot", "time", "signer", "wire_sha256"]):
            fail(C.RPC_DISAGREEMENT, "independent RPCs disagree on the anchor transaction")
    return {"chain": f"solana:{name}", "signature": ref["signature"], "slot": results[0]["slot"], "time": results[0]["time"],
            "signer": results[0]["signer"], "memo": memo, "finalized": True, "rpc_count": len(results),
            "network_class": cluster["network_class"], "anchorer_known": True}
