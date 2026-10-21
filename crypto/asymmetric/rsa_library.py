"""
Production-grade RSA using the `cryptography` package, with proper OAEP
padding for encryption and PSS padding for signatures. This is what you
should actually use for real secrets - `rsa_scratch.py` exists only to show
the underlying math.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEY_SIZE = 2048  # NIST/OWASP minimum recommendation as of 2026


def generate_keypair(key_size: int = KEY_SIZE):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def encrypt(message: bytes, public_key) -> bytes:
    """RSA-OAEP encryption (SHA-256). Note: RSA can only encrypt messages
    smaller than the key size minus padding overhead - for real file/data
    encryption, use RSA to wrap an AES key (hybrid encryption), not to
    encrypt the data directly."""
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt(ciphertext: bytes, private_key) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sign(message: bytes, private_key) -> bytes:
    """RSA-PSS signature (SHA-256) - the recommended padding scheme for
    RSA signatures (as opposed to the older, deterministic PKCS#1 v1.5)."""
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def serialize_private_key(private_key, password: bytes | None = None) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
