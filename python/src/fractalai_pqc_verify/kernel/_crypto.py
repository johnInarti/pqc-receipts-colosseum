"""Primitives for the Python kernel: SHA-256 (hashlib), Keccak-256 and strict Ed25519 verify (pure Python,
RFC 8032 / FIPS 202 reference algorithms — verification only, no secrets), ML-DSA-65 via the package backend
(dilithium-py / PQClean, guarded by its known-answer self-test). Not a CMVP/FIPS 140-3 validated module."""
from __future__ import annotations

import hashlib

from .. import mldsa

ML_DSA_65_PK_BYTES = 1952
ML_DSA_65_SIG_BYTES = 3309


def sha256hex(d: bytes | str) -> str:
    return hashlib.sha256(d.encode("utf-8") if isinstance(d, str) else d).hexdigest()


def kid_for_key(public_key_b64: str) -> str:
    return sha256hex(public_key_b64)[:16]


def mldsa_verify(sig: bytes, message: bytes, pk: bytes) -> bool:
    if len(sig) != ML_DSA_65_SIG_BYTES or len(pk) != ML_DSA_65_PK_BYTES:
        return False
    try:
        return mldsa.verify(pk, message, sig) is True
    except Exception:  # noqa: BLE001 — a backend problem is a rejection, never a crash
        return False


# ── Keccak-256 (original Keccak padding 0x01, as used by the EVM) ──
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(x, n):
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256hex(data: bytes) -> str:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * ((-len(msg)) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = _keccak_f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return "0x" + out.hex()


# ── Ed25519 strict verify (RFC 8032 §5.1.7, cofactorless, canonical encodings only) ──
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _encode(p) -> bytes:
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_G = _decode((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(sig: bytes, msg: bytes, pub: bytes) -> bool:
    try:
        if len(sig) != 64 or len(pub) != 32:
            return False
        a = _decode(pub)
        r = _decode(sig[:32])
        if a is None or r is None:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False
        k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
        sb = _mul(s, _G)
        ka = _mul(k, a)
        neg_ka = (_P - ka[0], ka[1], ka[2], _P - ka[3])
        return _encode(_add(sb, neg_ka)) == sig[:32]
    except Exception:  # noqa: BLE001
        return False
