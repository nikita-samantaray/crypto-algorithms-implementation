"""
HMAC (message authentication) and password hashing, using Python's
standard library `hmac`/`hashlib` plus PBKDF2 — these are already
correct, audited, constant-time implementations, so unlike the other
"scratch" modules there is no reason to reinvent them. This module exists
to demonstrate *correct usage* of these primitives, which is where most
real-world cryptographic bugs actually happen (e.g. comparing MACs with
`==` instead of a constant-time comparison, or hashing passwords with a
single fast SHA round instead of a slow, salted KDF).
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import os


def compute_hmac(message: bytes, key: bytes, digest: str = "sha256") -> bytes:
    """Computes HMAC(key, message). Use this to verify a message came from
    someone who holds `key` AND was not tampered with in transit."""
    return hmac_lib.new(key, message, digest).digest()


def verify_hmac(message: bytes, key: bytes, expected_mac: bytes, digest: str = "sha256") -> bool:
    """Verifies an HMAC using a constant-time comparison (hmac.compare_digest)
    to prevent timing attacks that could leak the correct MAC byte-by-byte."""
    computed = compute_hmac(message, key, digest)
    return hmac_lib.compare_digest(computed, expected_mac)


# --- Password hashing -------------------------------------------------------
# Never store raw password hashes (even salted single-round SHA-256) -
# GPUs can test billions of SHA-256 hashes per second. PBKDF2 (or better,
# bcrypt/scrypt/Argon2) deliberately makes each guess expensive.

PBKDF2_ITERATIONS = 390_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
SALT_SIZE = 16


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Returns (salt, hash). Store both - the salt is not secret, it just
    needs to be unique per password to defeat precomputed rainbow tables."""
    salt = salt or os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt, derived


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    _, derived = hash_password(password, salt)
    return hmac_lib.compare_digest(derived, expected_hash)


def encode_password_hash(salt: bytes, derived: bytes) -> str:
    """Encodes salt+hash as a single storable string, Django/Passlib-style:
    algorithm$iterations$salt_hex$hash_hex"""
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_encoded(password: str, encoded: str) -> bool:
    algo, iterations, salt_hex, hash_hex = encoded.split("$")
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    return hmac_lib.compare_digest(derived, expected)
