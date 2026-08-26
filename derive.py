#!/usr/bin/env python3
"""
The puzzle's derivation, done fast and without bip_utils.

`main.py` is the readable reference implementation; this module is the same
computation stripped down for brute force, and it is the shared core used by
both `bruteforce_fast.py` (CPU) and `gpu/gpu_bruteforce.py` (host-side
verification of GPU hits).

What is fixed and what varies
-----------------------------
The kitten image is public, so the 24-word mnemonic is public too. The ONLY
unknown is the BIP39 passphrase:

    seed    = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" + NFKD(passphrase), 2048, 64)
    address = P2WPKH(m/84'/0'/0'/0/0)

The mnemonic is therefore the PBKDF2 *password* (constant) and the passphrase
lives in the *salt*. That is the opposite of a seed-phrase search, and it means
nothing about the candidate can be precomputed: every guess pays the full 2048
HMAC-SHA512 iterations. That cost is the whole reason this puzzle is still open.

Why this is ~1.5x faster than the bip_utils path in `bruteforce.py`
-------------------------------------------------------------------
* `hashlib.pbkdf2_hmac` is OpenSSL's C implementation instead of a Python loop.
* Only three EC multiplications happen per candidate: `m/84'/0'/0'` are all
  hardened, which needs no public key at all, so pubkeys are only computed for
  the last two (non-hardened) levels plus the final child.
* No object allocation per candidate.

Self-test (verifies against the values published in the article):

    python3 derive.py --selftest
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata

from coincurve import PublicKey

# --------------------------------------------------------------------------- #
# puzzle constants
# --------------------------------------------------------------------------- #

CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The 24-word mnemonic of kitten.jpeg (sha256 of its base64 text as BIP39 entropy).
MNEMONIC = (
    "blossom educate state course sick fresh color divide number soap please pull "
    "glide weather join grit depart dynamic tenant leopard alter piano slight room"
)
MNEMONIC_NFKD = unicodedata.normalize("NFKD", MNEMONIC).encode()

# 0.01 BTC, generated from the kitten image + an unknown BIP39 passphrase.
TARGET_ADDRESS = "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r"
# The same image with an EMPTY passphrase -- the article's published result.
EMPTY_PASSPHRASE_ADDRESS = "bc1q57euh23y3qs2f9d5mtwpax5lqecfvrdkqce82a"

PATH = (84, 0, 0, 0, 0)  # m/84'/0'/0'/0/0, first three hardened

# --------------------------------------------------------------------------- #
# bech32 (BIP173) -- only witness v0 / 20-byte programs are needed here
# --------------------------------------------------------------------------- #

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def encode_p2wpkh(hash160: bytes, hrp: str = "bc") -> str:
    """witness v0 + 20-byte program -> bc1q... address"""
    data = [0]
    acc = bits = 0
    for byte in hash160:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def decode_p2wpkh(address: str) -> bytes:
    """bc1q... -> the 20-byte hash160. Raises ValueError on a bad address."""
    if address.lower() != address and address.upper() != address:
        raise ValueError("mixed case")
    addr = address.lower()
    pos = addr.rfind("1")
    if pos < 1:
        raise ValueError("no separator")
    hrp, body = addr[:pos], addr[pos + 1:]
    if any(c not in CHARSET for c in body):
        raise ValueError("character outside the bech32 charset")
    data = [CHARSET.index(c) for c in body]
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad bech32 checksum (bech32m/taproot addresses are not P2WPKH)")
    if data[0] != 0:
        raise ValueError(f"witness version {data[0]}, expected 0")
    acc = bits = 0
    out = bytearray()
    for v in data[1:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if len(out) != 20:
        raise ValueError(f"{len(out)}-byte witness program, expected 20")
    return bytes(out)


# --------------------------------------------------------------------------- #
# BIP32 / BIP39
# --------------------------------------------------------------------------- #


def _ckd_hardened(key: int, chain: bytes, index: int) -> tuple[int, bytes]:
    """Hardened child. Uses the parent PRIVATE key -- no EC multiplication."""
    I = hmac.new(
        chain,
        b"\x00" + key.to_bytes(32, "big") + (index | 0x80000000).to_bytes(4, "big"),
        hashlib.sha512,
    ).digest()
    return (int.from_bytes(I[:32], "big") + key) % CURVE_N, I[32:]


def _ckd_normal(key: int, chain: bytes, index: int) -> tuple[int, bytes]:
    """Non-hardened child. Needs the parent PUBLIC key -- one EC multiplication."""
    parent_pub = PublicKey.from_valid_secret(key.to_bytes(32, "big")).format()
    I = hmac.new(chain, parent_pub + index.to_bytes(4, "big"), hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + key) % CURVE_N, I[32:]


def seed_from_passphrase(passphrase: str) -> bytes:
    salt = b"mnemonic" + unicodedata.normalize("NFKD", passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", MNEMONIC_NFKD, salt, 2048, 64)


def hash160_from_passphrase(passphrase: str, path: tuple = PATH) -> bytes:
    """The 20-byte witness program at `path` for this passphrase."""
    I = hmac.new(b"Bitcoin seed", seed_from_passphrase(passphrase), hashlib.sha512).digest()
    key, chain = int.from_bytes(I[:32], "big"), I[32:]
    purpose, coin, account, change, index = path
    for i in (purpose, coin, account):
        key, chain = _ckd_hardened(key, chain, i)
    for i in (change, index):
        key, chain = _ckd_normal(key, chain, i)
    pub = PublicKey.from_valid_secret(key.to_bytes(32, "big")).format()
    return hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()


def address_from_passphrase(passphrase: str, path: tuple = PATH) -> str:
    return encode_p2wpkh(hash160_from_passphrase(passphrase, path))


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #


def selftest() -> int:
    import base64
    from pathlib import Path

    ok = True

    def check(label, passed, detail=""):
        nonlocal ok
        ok &= bool(passed)
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}" + (f"  {detail}" if detail else ""))

    print("bech32 round-trip")
    h = decode_p2wpkh(TARGET_ADDRESS)
    check("decode/encode target", encode_p2wpkh(h) == TARGET_ADDRESS, h.hex())
    try:
        decode_p2wpkh(TARGET_ADDRESS[:-1])
        check("rejects the truncated address from the old README", False)
    except ValueError as exc:
        check("rejects the truncated address from the old README", True, str(exc))

    print("the article's published values")
    image = Path(__file__).resolve().parent / "kitten.jpeg"
    if image.exists():
        b64 = base64.b64encode(image.read_bytes())
        digest = hashlib.sha256(b64).hexdigest()
        check(
            "sha256 of base64(kitten.jpeg)",
            digest == "1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed",
            digest,
        )
    else:
        print("  [SKIP] kitten.jpeg not next to derive.py")
    got = address_from_passphrase("")
    check("empty passphrase -> the article's address", got == EMPTY_PASSPHRASE_ADDRESS, got)

    print("BIP39/BIP84 official test vector")
    # BIP84 test vectors, mnemonic "abandon ... about", first receiving address.
    global MNEMONIC_NFKD
    saved = MNEMONIC_NFKD
    try:
        MNEMONIC_NFKD = (" ".join(["abandon"] * 11 + ["about"])).encode()
        got = address_from_passphrase("")
        check("m/84'/0'/0'/0/0", got == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", got)
    finally:
        MNEMONIC_NFKD = saved

    print("passphrase sensitivity")
    a, b = address_from_passphrase("a"), address_from_passphrase("A")
    check("case matters", a != b)
    check("target is not reachable with an empty passphrase", address_from_passphrase("") != TARGET_ADDRESS)

    print(f"\n{'ALL CHECKS PASSED' if ok else 'SOME CHECKS FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    import argparse
    import sys
    import time

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", type=int, metavar="N", help="time N derivations on one core")
    ap.add_argument("passphrase", nargs="?", help="print the address for this passphrase")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.bench:
        t0 = time.perf_counter()
        for i in range(args.bench):
            address_from_passphrase(f"bench{i}")
        dt = time.perf_counter() - t0
        print(f"{args.bench / dt:,.0f} candidates/s on one core")
        sys.exit(0)
    phrase = args.passphrase or ""
    print(f"passphrase : {phrase!r}")
    print(f"address    : {address_from_passphrase(phrase)}")
