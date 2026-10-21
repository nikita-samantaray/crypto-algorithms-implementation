# Cryptography Algorithms Implementation Project

A Python toolkit that implements and demonstrates core cryptographic primitives across four categories: classical ciphers, symmetric encryption (AES), asymmetric encryption (RSA), and hashing/integrity (SHA-256, HMAC, password hashing). Built as a cybersecurity internship project.

## Why "scratch" AND "library" versions?

Every modern primitive (AES, RSA) is implemented **twice**:

1. **`*_scratch.py`** — built from first principles (raw math, no crypto library) to prove understanding of the actual algorithm: AES's S-box/ShiftRows/MixColumns rounds, RSA's modular exponentiation and key generation, SHA-256's compression function.
2. **`*_library.py`** — the version you'd actually ship, using the audited, constant-time [`cryptography`](https://cryptography.io) package with proper padding (OAEP/PSS) and authenticated encryption (AES-GCM).

Every scratch implementation is **verified against official test vectors or the standard library** in the test suite — this isn't "looks right," it's bit-for-bit confirmed correct (see [Verification](#verification) below).

## What's implemented

| Category | File | Algorithm |
|---|---|---|
| Classical | `crypto/classical/caesar.py` | Caesar cipher + brute-force/frequency-analysis cryptanalysis |
| Classical | `crypto/classical/vigenere.py` | Vigenère cipher + Kasiski examination helper |
| Symmetric | `crypto/symmetric/aes_scratch.py` | AES-128 from scratch (full FIPS-197 key schedule & round functions), ECB mode |
| Symmetric | `crypto/symmetric/aes_library.py` | AES-256-GCM via `cryptography`, password-derived keys (PBKDF2) |
| Asymmetric | `crypto/asymmetric/rsa_scratch.py` | RSA from scratch: Miller-Rabin prime generation, key generation, textbook encrypt/decrypt/sign/verify |
| Asymmetric | `crypto/asymmetric/rsa_library.py` | RSA-2048 via `cryptography`, OAEP encryption + PSS signatures |
| Hashing | `crypto/hashing/sha256_scratch.py` | SHA-256 from scratch (full FIPS-180-4 compression function) |
| Hashing | `crypto/hashing/integrity.py` | HMAC (constant-time verify), PBKDF2 password hashing (OWASP-recommended 390k iterations) |

## Quick start

```bash
git clone https://github.com/<your-username>/crypto-algorithms-implementation.git
cd crypto-algorithms-implementation
pip install -r requirements.txt

# Run every algorithm end-to-end with sample data
python -m crypto.cli demo

# Try individual algorithms
python -m crypto.cli caesar "Attack at Dawn" --shift 3
python -m crypto.cli vigenere "Attack at Dawn" --key LEMON
python -m crypto.cli hash "some text"
python -m crypto.cli password-hash "my-password"
```

### Running tests

```bash
python -m unittest discover -s tests -v
```

## Verification

The from-scratch implementations aren't just "it ran without crashing" — they're checked against ground truth:

- **AES-128**: encrypts the **official FIPS-197 Appendix B test vector** and must match the published ciphertext byte-for-byte.
- **SHA-256**: hashes a dozen inputs of varying length (including ones that straddle the 56/64-byte padding boundary) and compares every digest against Python's own `hashlib.sha256` — if even one bit differed, the test would fail.
- **RSA**: verifies the core correctness property (`decrypt(encrypt(m)) == m` and `verify(sign(m)) == True`) and that tampering is correctly rejected.

34 tests total, run automatically on every push via GitHub Actions (`.github/workflows/ci.yml`).

## Example output

```
======================================================================
2. SYMMETRIC ENCRYPTION (AES)
======================================================================
AES-128 (scratch) single block -> 69c4e0d86a7b0430d8cdb78070b4c55a  (matches FIPS-197 test vector)
AES-256-GCM (library) encrypted 47 bytes -> 63 byte ciphertext+tag
Decrypted back correctly: True

======================================================================
3. ASYMMETRIC ENCRYPTION (RSA)
======================================================================
RSA-2048-OAEP (library) encrypt/decrypt roundtrip correct: True
RSA-PSS signature verifies: True
RSA-PSS signature rejects tampering: True
```

## Project structure

```
crypto-algorithms-implementation/
├── crypto/
│   ├── classical/
│   │   ├── caesar.py              # Caesar cipher + cryptanalysis
│   │   └── vigenere.py            # Vigenere cipher + Kasiski examination
│   ├── symmetric/
│   │   ├── aes_scratch.py         # AES-128 from scratch (FIPS-197)
│   │   └── aes_library.py         # AES-256-GCM, production-grade
│   ├── asymmetric/
│   │   ├── rsa_scratch.py         # RSA from scratch (keygen, encrypt, sign)
│   │   └── rsa_library.py         # RSA-2048-OAEP/PSS, production-grade
│   ├── hashing/
│   │   ├── sha256_scratch.py      # SHA-256 from scratch (FIPS-180-4)
│   │   └── integrity.py           # HMAC + PBKDF2 password hashing
│   └── cli.py                     # command-line demo
├── tests/                         # 34 unit tests, all algorithms
├── docs/
│   └── SECURITY_NOTES.md          # why "textbook" crypto ≠ production crypto
├── .github/workflows/ci.yml       # GitHub Actions: installs deps, tests, demo
└── requirements.txt
```

## Skills demonstrated

- Core cryptographic algorithm internals: AES round structure (SubBytes/ShiftRows/MixColumns/AddRoundKey), RSA number theory (modular exponentiation, Miller-Rabin primality, extended Euclidean algorithm), SHA-256 compression function
- The gap between **textbook crypto** (what's taught) and **production crypto** (what's safe to ship) — padding oracle risks, ECB pattern leakage, authenticated encryption, constant-time comparison
- Classical cryptanalysis: frequency analysis, Kasiski examination
- Secure coding practices: salted/iterated password hashing, constant-time MAC comparison, random nonce generation
- Test-driven development against official standards (FIPS-197, FIPS-180-4) and OWASP guidance
- CI/CD basics via GitHub Actions

## Important security notes

This repository exists to **teach how these algorithms work internally**. The `*_scratch.py` modules are not constant-time, are unaudited, and (for RSA/AES-ECB) deliberately demonstrate textbook/insecure modes for educational contrast. **Never use the scratch modules for real secrets** — use the `*_library.py` modules, which wrap the audited `cryptography` package, for anything real. See `docs/SECURITY_NOTES.md` for a full breakdown of why this distinction matters.

## License

MIT — see `LICENSE`.
