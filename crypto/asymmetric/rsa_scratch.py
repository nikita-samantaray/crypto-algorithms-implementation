"""
RSA implemented from scratch (educational), demonstrating key generation,
encryption/decryption, and digital signatures using only Python's built-in
big-integer arithmetic.

⚠️ SECURITY WARNING: This is a teaching implementation using small (demo)
key sizes and textbook (unpadded) RSA. Textbook RSA is deterministic and
malleable - real systems must use OAEP padding for encryption and PSS
padding for signatures (both provided by `rsa_library.py`, backed by the
audited `cryptography` package). Never use this module for real secrets.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


def _is_probable_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # set top & bottom bit
        if _is_probable_prime(candidate):
            return candidate


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int


@dataclass
class KeyPair:
    public: PublicKey
    private: PrivateKey


def generate_keypair(bits: int = 1024, e: int = 65537) -> KeyPair:
    """Generates an RSA keypair. `bits` is the total modulus size (each
    prime is `bits // 2` bits). 1024 bits is used as a fast *teaching*
    default; real systems require >= 2048 bits (see rsa_library.py)."""
    half = bits // 2
    p = _generate_prime(half)
    q = _generate_prime(half)
    while p == q:
        q = _generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    if __import__("math").gcd(e, phi) != 1:
        raise ValueError("Chosen e is not coprime with phi(n); retry key generation")

    d = _modinv(e, phi)
    return KeyPair(public=PublicKey(n=n, e=e), private=PrivateKey(n=n, d=d))


def _int_to_bytes(x: int) -> bytes:
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def encrypt_int(message: int, public_key: PublicKey) -> int:
    """Textbook RSA encryption: c = m^e mod n. `message` must be < n."""
    if message >= public_key.n:
        raise ValueError("Message too large for this key size (use hybrid encryption for real data)")
    return pow(message, public_key.e, public_key.n)


def decrypt_int(ciphertext: int, private_key: PrivateKey) -> int:
    return pow(ciphertext, private_key.d, private_key.n)


def encrypt_bytes(message: bytes, public_key: PublicKey) -> bytes:
    m_int = _bytes_to_int(message)
    c_int = encrypt_int(m_int, public_key)
    return _int_to_bytes(c_int)


def decrypt_bytes(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    c_int = _bytes_to_int(ciphertext)
    m_int = decrypt_int(c_int, private_key)
    return _int_to_bytes(m_int)


def sign(message: bytes, private_key: PrivateKey) -> int:
    """Textbook RSA signature: sign the SHA-256 hash of the message with
    the private key (s = hash(m)^d mod n)."""
    digest = hashlib.sha256(message).digest()
    h_int = _bytes_to_int(digest)
    if h_int >= private_key.n:
        h_int %= private_key.n
    return pow(h_int, private_key.d, private_key.n)


def verify(message: bytes, signature: int, public_key: PublicKey) -> bool:
    digest = hashlib.sha256(message).digest()
    h_int = _bytes_to_int(digest) % public_key.n
    recovered = pow(signature, public_key.e, public_key.n)
    return recovered == h_int
