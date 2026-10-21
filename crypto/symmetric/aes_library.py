"""
Production-grade AES using the `cryptography` package (OpenSSL-backed,
audited, constant-time). This is what you should actually use for real
secrets - `aes_scratch.py` exists only to show how the algorithm works
internally.

Uses AES-256-GCM: authenticated encryption (confidentiality + integrity),
a random nonce per message, and no manual padding required.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

NONCE_SIZE = 12  # 96 bits, recommended size for GCM
KEY_SIZE = 32  # AES-256
SALT_SIZE = 16
PBKDF2_ITERATIONS = 390_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256


@dataclass
class EncryptedPayload:
    salt: bytes
    nonce: bytes
    ciphertext: bytes  # includes the GCM auth tag, appended by AESGCM

    def to_bytes(self) -> bytes:
        return self.salt + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedPayload":
        salt, nonce, ciphertext = (
            data[:SALT_SIZE],
            data[SALT_SIZE : SALT_SIZE + NONCE_SIZE],
            data[SALT_SIZE + NONCE_SIZE :],
        )
        return cls(salt=salt, nonce=nonce, ciphertext=ciphertext)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, password: str, associated_data: bytes | None = None) -> EncryptedPayload:
    """Encrypts `plaintext` with a password-derived AES-256-GCM key.

    A fresh random salt and nonce are generated per call. `associated_data`
    is authenticated but not encrypted (e.g. a message header or metadata).
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return EncryptedPayload(salt=salt, nonce=nonce, ciphertext=ciphertext)


def decrypt(payload: EncryptedPayload, password: str, associated_data: bytes | None = None) -> bytes:
    """Decrypts a payload produced by `encrypt`. Raises
    `cryptography.exceptions.InvalidTag` if the password is wrong or the
    ciphertext/associated_data was tampered with."""
    key = derive_key(password, payload.salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(payload.nonce, payload.ciphertext, associated_data)


def encrypt_to_bytes(plaintext: bytes, password: str) -> bytes:
    """Convenience wrapper returning a single self-contained blob
    (salt || nonce || ciphertext+tag) ready to store or transmit."""
    return encrypt(plaintext, password).to_bytes()


def decrypt_from_bytes(blob: bytes, password: str) -> bytes:
    return decrypt(EncryptedPayload.from_bytes(blob), password)
