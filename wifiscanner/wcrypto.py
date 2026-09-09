"""Verified pure-Python crypto for the WPA/WPA2/WPA3 laboratory.

Everything here is stdlib-only so the lab runs anywhere (the project's
zero-mandatory-dependency rule), and every primitive is checked against a
published test vector in ``tests/test_wpalab.py``:

* AES-128/192/256 block encrypt/decrypt  — FIPS-197 known answers
* AES-CCM                                — RFC 3610 test vector
* AES-GCM (GHASH)                        — NIST GCM test vector
* AES-CMAC                               — RFC 4493 test vectors
* AES-KW / AES-KWP                       — RFC 3394 / RFC 5649
* RC4 (WEP/TKIP framing)                 — standard textbook vector
* PBKDF2-SHA1 PMK derivation             — RFC 6070 + the canonical 802.11
  ``password``/``IEEE`` vector printed in every 802.11i tutorial
* PRF PTK derivation + HMAC-SHA1 / HMAC-MD5 handshake MICs — exercised
  end-to-end against lab captures built by ``wpalab.make_fixture``

Teaching note that stays true throughout the lab: a passphrase alone is
NOT enough to decrypt a capture. You need the 4-way handshake (or the PMK
supplied by the instructor) because the per-session PTK is derived from
both. That is precisely why the exercises treat the handshake as the
"authorization to decrypt" artifact.
"""
from __future__ import annotations

import hashlib
import hmac

__all__ = ["aes_encrypt_block", "aes_decrypt_block", "ccm_encrypt",
           "ccm_decrypt", "gcm_encrypt", "gcm_decrypt", "cmac_aes",
           "kw_wrap", "kw_unwrap", "kwp_wrap", "kwp_unwrap", "rc4",
           "pmk_from_passphrase", "prf_sha1", "derive_ptk", "handshake_mic",
           "CryptoError"]


class CryptoError(ValueError):
    """Raised when authenticated decryption fails (bad key / corrupt data)."""


# ---------------------------------------------------------------- AES core

_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16)

_ISBOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
         0xd8, 0xab, 0x4d)


def _expand_key(key: bytes) -> list:
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise CryptoError("AES key must be 16/24/32 bytes")
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[-1])
        if i % nk == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= _RCON[i // nk - 1]
        elif nk == 8 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[-nk][j] ^ t[j] for j in range(4)])
    return w  # round keys as 4-byte words


def _xtimes(a: int, n: int) -> int:
    for _ in range(n):
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
    return a


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """One 16-byte block of AES (108 sbox lookups, FIPS-197 layout)."""
    if len(block) != 16:
        raise CryptoError("AES block must be 16 bytes")
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    s = [block[c * 4 + r] ^ w[c][r] for c in range(4) for r in range(4)]
    # s is flat, index = row + 4*col (column-major, as in FIPS-197)
    for rnd in range(1, nr + 1):
        s = [_SBOX[b] for b in s]
        s = [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]
        if rnd != nr:
            out = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = (s[4 * c + r] for r in range(4))
                out[4 * c] = _xtimes(a0, 1) ^ (_xtimes(a1, 1) ^ a1) ^ a2 ^ a3
                out[4 * c + 1] = a0 ^ _xtimes(a1, 1) ^ (_xtimes(a2, 1) ^ a2) ^ a3
                out[4 * c + 2] = a0 ^ a1 ^ _xtimes(a2, 1) ^ (_xtimes(a3, 1) ^ a3)
                out[4 * c + 3] = (_xtimes(a0, 1) ^ a0) ^ a1 ^ a2 ^ _xtimes(a3, 1)
            s = out
        for c in range(4):
            for r in range(4):
                s[r + 4 * c] ^= w[4 * rnd + c][r]
    return bytes(s)


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise CryptoError("AES block must be 16 bytes")
    w = _expand_key(key)
    nr = len(key) // 4 + 6
    s = [block[c * 4 + r] ^ w[4 * nr + c][r] for c in range(4) for r in range(4)]
    for rnd in range(nr - 1, -1, -1):
        # InvShiftRows
        s = [s[(r + 4 * ((c - r) % 4))] for c in range(4) for r in range(4)]
        s = [_ISBOX[b] for b in s]
        for c in range(4):
            for r in range(4):
                s[r + 4 * c] ^= w[4 * rnd + c][r]
        if rnd:
            out = [0] * 16
            for c in range(4):
                a0, a1, a2, a3 = (s[4 * c + r] for r in range(4))
                def m(a, n):      # GF multiply by n via xtimes chain
                    r0 = 0
                    b = a
                    while n:
                        if n & 1:
                            r0 ^= b
                        b = _xtimes(b, 1)
                        n >>= 1
                    return r0
                out[4 * c] = m(a0, 14) ^ m(a1, 11) ^ m(a2, 13) ^ m(a3, 9)
                out[4 * c + 1] = m(a0, 9) ^ m(a1, 14) ^ m(a2, 11) ^ m(a3, 13)
                out[4 * c + 2] = m(a0, 13) ^ m(a1, 9) ^ m(a2, 14) ^ m(a3, 11)
                out[4 * c + 3] = m(a0, 11) ^ m(a1, 13) ^ m(a2, 9) ^ m(a3, 14)
            s = out
    return bytes(s)


# ------------------------------------------------------------------ counter

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# -------------------------------------------------------------------- CCM

def ccm_encrypt(key: bytes, nonce: bytes, msg: bytes, aad: bytes = b"",
                mic_len: int = 8) -> bytes:
    """AES-CCM (RFC 3610). Returns ciphertext || tag."""
    if not (7 <= len(nonce) <= 13):
        raise CryptoError("CCM nonce must be 7..13 bytes")
    L = 15 - len(nonce)
    mic_len = int(mic_len)
    flags = (((mic_len - 2) // 2) << 3) | (L - 1)
    if aad:
        flags |= 0x40
    b0 = bytes([flags]) + nonce + len(msg).to_bytes(L, "big")
    if aad:
        if len(aad) < 0xFF00:
            hdr = len(aad).to_bytes(2, "big") + aad
        else:
            hdr = b"\xff\xfe" + len(aad).to_bytes(4, "big") + aad
        mac_in = b0 + hdr + b"\x00" * (-len(hdr) % 16) + msg
    else:
        mac_in = b0 + msg
    mac_in += b"\x00" * (-len(mac_in) % 16)
    x = b"\x00" * 16
    for off in range(0, len(mac_in), 16):
        x = aes_encrypt_block(key, _xor(x, mac_in[off:off + 16]))
    tag = x[:mic_len]
    ctr_flags = bytes([L - 1])
    ks = b""
    for i in range(0, len(msg) + 15, 16):
        ks += aes_encrypt_block(
            key, ctr_flags + nonce + (i // 16 + 1).to_bytes(L, "big"))
    s0 = aes_encrypt_block(key, ctr_flags + nonce + b"\x00" * L)
    return _xor(msg, ks[:len(msg)]) + _xor(tag, s0[:mic_len])


def ccm_decrypt(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes = b"",
                mic_len: int = 8) -> bytes:
    if len(ct_tag) < mic_len:
        raise CryptoError("CCM input shorter than its MIC")
    ct, tag = ct_tag[:-mic_len], ct_tag[-mic_len:]
    L = 15 - len(nonce)
    ctr_flags = bytes([L - 1])
    ks = b""
    for i in range(0, len(ct) + 15, 16):
        ks += aes_encrypt_block(
            key, ctr_flags + nonce + (i // 16 + 1).to_bytes(L, "big"))
    msg = _xor(ct, ks[:len(ct)])
    expect = ccm_encrypt(key, nonce, msg, aad, mic_len)[-mic_len:]
    if not hmac.compare_digest(expect, tag):
        raise CryptoError("CCM authentication failed")
    return msg


# -------------------------------------------------------------------- GCM

def _ghash_mul(x: int, y: int) -> int:
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1000000000000000000000000000000 if v & 1 else 0)
    return z


def _ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    hint = int.from_bytes(h, "big")
    data = aad + b"\x00" * (-len(aad) % 16) + ct + b"\x00" * (-len(ct) % 16) \
        + (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    y = 0
    for off in range(0, len(data), 16):
        y = _ghash_mul(y ^ int.from_bytes(data[off:off + 16], "big"), hint)
    return y.to_bytes(16, "big")


def _gctr(key: bytes, j0: bytes, data: bytes) -> bytes:
    ks = b""
    counter = int.from_bytes(j0, "big")
    mod = (1 << 32) - 1
    for i in range(0, len(data), 16):
        counter = (counter & ~mod) | ((counter + 1) & mod)
        ks += aes_encrypt_block(key, counter.to_bytes(16, "big"))
    return _xor(data, ks[:len(data)])


def gcm_encrypt(key: bytes, nonce: bytes, msg: bytes, aad: bytes = b"",
                tag_len: int = 16) -> bytes:
    if len(nonce) == 12:
        j0 = nonce + b"\x00\x00\x00\x01"
    else:
        j0 = _ghash(aes_encrypt_block(key, b"\x00" * 16), b"", nonce)
    ct = _gctr(key, j0, msg)
    s = _ghash(aes_encrypt_block(key, b"\x00" * 16), aad, ct)
    tag = _xor(s, aes_encrypt_block(key, j0))[:tag_len]
    return ct + tag


def gcm_decrypt(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes = b"",
                tag_len: int = 16) -> bytes:
    if len(ct_tag) < tag_len:
        raise CryptoError("GCM input shorter than its tag")
    ct, tag = ct_tag[:-tag_len], ct_tag[-tag_len:]
    if len(nonce) == 12:
        j0 = nonce + b"\x00\x00\x00\x01"
    else:
        j0 = _ghash(aes_encrypt_block(key, b"\x00" * 16), b"", nonce)
    s = _ghash(aes_encrypt_block(key, b"\x00" * 16), aad, ct)
    expect = _xor(s, aes_encrypt_block(key, j0))[:tag_len]
    if not hmac.compare_digest(expect, tag):
        raise CryptoError("GCM authentication failed")
    return _gctr(key, j0, ct)


# ---------------------------------------------------------------- CMAC (4493)

def _cmac_subkeys(key: bytes) -> tuple:
    l = aes_encrypt_block(key, b"\x00" * 16)
    def dbl(b: bytes) -> bytes:
        v = int.from_bytes(b, "big")
        carry = v >> 127
        v = ((v << 1) & ((1 << 128) - 1)) ^ (0x87 if carry else 0)
        return v.to_bytes(16, "big")
    k1 = dbl(l)
    return k1, dbl(k1)


def cmac_aes(key: bytes, msg: bytes) -> bytes:
    """AES-CMAC-128 per RFC 4493."""
    k1, k2 = _cmac_subkeys(key)
    n = max(1, -(-len(msg) // 16))
    if len(msg) and len(msg) % 16 == 0:
        last = _xor(msg[(n - 1) * 16:], k1)
    else:
        tail = msg[(n - 1) * 16:] + b"\x80"
        tail += b"\x00" * (16 - len(tail))
        last = _xor(tail, k2)
    x = b"\x00" * 16
    for off in range(0, (n - 1) * 16, 16):
        x = aes_encrypt_block(key, _xor(x, msg[off:off + 16]))
    return aes_encrypt_block(key, _xor(x, last))


# --------------------------------------------------------- AES-KW / KWP

_KW_IV = b"\xa6" * 8


def kw_wrap(kek: bytes, plain: bytes) -> bytes:
    """RFC 3394 key wrap; plaintext must be >= 16 bytes and 8-aligned."""
    if len(plain) < 16 or len(plain) % 8:
        raise CryptoError("AES-KW plaintext must be >=16 and 8-byte aligned")
    n = len(plain) // 8
    a = _KW_IV
    r = [plain[8 * i:8 * i + 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            b = aes_encrypt_block(kek, a + r[i])
            t = n * j + i + 1
            a = (int.from_bytes(b[:8], "big") ^ t).to_bytes(8, "big")
            r[i] = b[8:]
    return a + b"".join(r)


def kw_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    if len(wrapped) < 24 or len(wrapped) % 8:
        raise CryptoError("AES-KW ciphertext must be >=24 and 8-byte aligned")
    n = len(wrapped) // 8 - 1
    a = wrapped[:8]
    r = [wrapped[8 * (i + 1):8 * (i + 2)] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            b = aes_decrypt_block(
                kek, (int.from_bytes(a, "big") ^ t).to_bytes(8, "big") + r[i])
            a, r[i] = b[:8], b[8:]
    if a != _KW_IV:
        raise CryptoError("AES-KW integrity check failed")
    return b"".join(r)


_KWP_IV = b"\xa6\x59\x59\xa6"


def kwp_wrap(kek: bytes, plain: bytes) -> bytes:
    """RFC 5649 key wrap with padding (802.11 wraps key-data this way)."""
    m = len(plain)
    padded = plain + b"\x00" * (-m % 8)
    if len(padded) == 8:                    # single 8-byte block: AES-ECB
        return aes_encrypt_block(kek, _KWP_IV + m.to_bytes(4, "big") + padded)
    return kw_wrap(kek, _KWP_IV + m.to_bytes(4, "big") + padded)


def kwp_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    if len(wrapped) == 16:
        alt = aes_decrypt_block(kek, wrapped)
    else:
        alt = kw_unwrap(kek, wrapped)
    if alt[:4] != _KWP_IV:
        raise CryptoError("AES-KWP integrity check failed")
    m = int.from_bytes(alt[4:8], "big")
    data = alt[8:8 + m]
    if m > len(alt) - 8 or len(alt) - 8 - m > 7 or alt[8 + m:].strip(b"\x00"):
        raise CryptoError("AES-KWP padding check failed")
    return data


# -------------------------------------------------------------------- RC4

def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# ------------------------------------------------- 802.11 key derivation

def pmk_from_passphrase(passphrase: str, ssid: str) -> bytes:
    """802.11 PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               ssid.encode("utf-8"), 4096, 32)


def prf_sha1(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    """802.11 PRF-n: HMAC-SHA1(key, label || 0x00 || data || counter)."""
    out = b""
    i = 0
    while len(out) < length:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]),
                        hashlib.sha1).digest()
        i += 1
    return out[:length]


# cipher -> (kck_len, kek_len, tk_len, ptk_len)
CIPHER_KEY_SIZES = {
    "ccmp": (16, 16, 16, 64), "ccmp-128": (16, 16, 16, 64),
    "tkip": (16, 16, 16, 64),
    "gcmp": (16, 16, 16, 64), "gcmp-128": (16, 16, 16, 64),
    "ccmp-256": (24, 32, 32, 88), "gcmp-256": (24, 32, 32, 88),
}


def derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
               anonce: bytes, snonce: bytes,
               cipher: str = "ccmp") -> dict:
    """Derive the pairwise transient key set from a completed handshake."""
    sizes = CIPHER_KEY_SIZES.get(cipher, CIPHER_KEY_SIZES["ccmp"])
    data = (min(ap_mac, sta_mac) + max(ap_mac, sta_mac)
            + min(anonce, snonce) + max(anonce, snonce))
    ptk = prf_sha1(pmk, b"Pairwise key expansion", data, sizes[3])
    return {"ptk": ptk,
            "kck": ptk[:sizes[0]],
            "kek": ptk[sizes[0]:sizes[0] + sizes[1]],
            "tk": ptk[sizes[0] + sizes[1]:sizes[0] + sizes[1] + sizes[2]]}


def handshake_mic(kck: bytes, eapol_frame_zeroed: bytes,
                  descriptor_version: int = 2) -> bytes:
    """802.11 handshake MIC for the EAPOL-Key frame with its MIC zeroed."""
    if descriptor_version == 1:
        return hmac.new(kck[:16], eapol_frame_zeroed, hashlib.md5).digest()
    if descriptor_version == 3:
        return cmac_aes(kck[:16], eapol_frame_zeroed)
    return hmac.new(kck[:16], eapol_frame_zeroed, hashlib.sha1).digest()[:16]
