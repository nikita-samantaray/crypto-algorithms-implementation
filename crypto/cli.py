"""
Command-line demo for the Cryptography Algorithms Implementation Project.

Usage:
    python -m crypto.cli demo          # runs all algorithms end to end
    python -m crypto.cli caesar "text" --shift 3
    python -m crypto.cli vigenere "text" --key LEMON
    python -m crypto.cli hash "text"
    python -m crypto.cli password-hash "mypassword"
"""

import argparse
import textwrap

from crypto.classical import caesar, vigenere
from crypto.symmetric import aes_scratch, aes_library
from crypto.asymmetric import rsa_scratch, rsa_library
from crypto.hashing import sha256_scratch, integrity


def _section(title: str):
    print(f"\n{'='*70}\n{title}\n{'='*70}")


def cmd_demo(_args):
    _section("1. CLASSICAL CIPHERS")
    pt = "Attack at Dawn"
    ct = caesar.encrypt(pt, 3)
    print(f"Caesar  | plaintext='{pt}' shift=3 -> ciphertext='{ct}'")
    print(f"Caesar  | decrypted back: '{caesar.decrypt(ct, 3)}'")

    ct2 = vigenere.encrypt(pt, "LEMON")
    print(f"Vigenere| plaintext='{pt}' key='LEMON' -> ciphertext='{ct2}'")
    print(f"Vigenere| decrypted back: '{vigenere.decrypt(ct2, 'LEMON')}'")

    _section("2. SYMMETRIC ENCRYPTION (AES)")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    enc_block = aes_scratch.encrypt_block(block, key)
    print(f"AES-128 (scratch) single block -> {enc_block.hex()}  (matches FIPS-197 test vector)")

    msg = b"Secret internship project report - confidential"
    payload = aes_library.encrypt(msg, "strong-password-123")
    recovered = aes_library.decrypt(payload, "strong-password-123")
    print(f"AES-256-GCM (library) encrypted {len(msg)} bytes -> {len(payload.ciphertext)} byte ciphertext+tag")
    print(f"Decrypted back correctly: {recovered == msg}")

    _section("3. ASYMMETRIC ENCRYPTION (RSA)")
    priv, pub = rsa_library.generate_keypair(key_size=2048)
    rsa_msg = b"session-key-bytes"
    rsa_ct = rsa_library.encrypt(rsa_msg, pub)
    rsa_pt = rsa_library.decrypt(rsa_ct, priv)
    print(f"RSA-2048-OAEP (library) encrypt/decrypt roundtrip correct: {rsa_pt == rsa_msg}")

    sig = rsa_library.sign(b"this document is authentic", priv)
    print(f"RSA-PSS signature verifies: {rsa_library.verify(b'this document is authentic', sig, pub)}")
    print(f"RSA-PSS signature rejects tampering: {not rsa_library.verify(b'tampered document', sig, pub)}")

    _section("4. HASHING & INTEGRITY")
    text = b"integrity check this"
    digest = sha256_scratch.sha256_hexdigest(text)
    print(f"SHA-256 (scratch) of {text!r}:\n  {digest}")

    salt, h = integrity.hash_password("correct horse battery staple")
    encoded = integrity.encode_password_hash(salt, h)
    print(f"\nPassword hash (PBKDF2-HMAC-SHA256, 390k iterations):\n  {encoded}")
    print(f"Verifies with correct password: {integrity.verify_encoded('correct horse battery staple', encoded)}")
    print(f"Rejects wrong password: {not integrity.verify_encoded('wrong-password', encoded)}")

    mac = integrity.compute_hmac(b"important message", b"shared-secret-key")
    print(f"\nHMAC-SHA256 tag: {mac.hex()}")
    print(f"Verifies correctly: {integrity.verify_hmac(b'important message', b'shared-secret-key', mac)}")

    print("\nAll demonstrations completed successfully.\n")


def cmd_caesar(args):
    if args.decrypt:
        print(caesar.decrypt(args.text, args.shift))
    else:
        print(caesar.encrypt(args.text, args.shift))


def cmd_vigenere(args):
    if args.decrypt:
        print(vigenere.decrypt(args.text, args.key))
    else:
        print(vigenere.encrypt(args.text, args.key))


def cmd_hash(args):
    print(sha256_scratch.sha256_hexdigest(args.text.encode("utf-8")))


def cmd_password_hash(args):
    salt, h = integrity.hash_password(args.password)
    print(integrity.encode_password_hash(salt, h))


def main():
    parser = argparse.ArgumentParser(
        description="Cryptography Algorithms Implementation Project - CLI demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__ or ""),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Run every algorithm end-to-end with sample data").set_defaults(func=cmd_demo)

    p = sub.add_parser("caesar", help="Caesar cipher")
    p.add_argument("text")
    p.add_argument("--shift", type=int, default=3)
    p.add_argument("--decrypt", action="store_true")
    p.set_defaults(func=cmd_caesar)

    p = sub.add_parser("vigenere", help="Vigenere cipher")
    p.add_argument("text")
    p.add_argument("--key", required=True)
    p.add_argument("--decrypt", action="store_true")
    p.set_defaults(func=cmd_vigenere)

    p = sub.add_parser("hash", help="SHA-256 hash of text")
    p.add_argument("text")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("password-hash", help="PBKDF2 password hash")
    p.add_argument("password")
    p.set_defaults(func=cmd_password_hash)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
