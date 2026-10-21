# Security Notes: Textbook Crypto vs. Production Crypto

This document explains, module by module, why the "from scratch"
implementations in this repo are for learning, not production — and what
the real risks are. Understanding *why* a scheme is broken is arguably more
valuable than memorizing "don't roll your own crypto."

## Classical ciphers (`crypto/classical/`)

Caesar and Vigenère are **not cryptographically secure by any modern
standard**. Caesar has only 25 possible keys (trivial brute force).
Vigenère resists simple frequency analysis but falls to Kasiski examination
once the key is shorter than the message (which it always is in practice).
They're included purely to build intuition for substitution, key reuse, and
why one-time pads (which Vigenère resembles, but with a *repeating* key)
need truly random, message-length, single-use keys to be secure.

## AES (`crypto/symmetric/`)

**`aes_scratch.py` risks:**
- **Not constant-time.** The S-box lookups and branching in this Python
  implementation take data-dependent time, which in principle leaks key
  bits to an attacker who can measure timing precisely (a side-channel
  attack). Production AES implementations use bitsliced or
  hardware-accelerated (AES-NI) constant-time code.
- **ECB mode leaks patterns.** Identical 16-byte plaintext blocks always
  encrypt to identical ciphertext blocks. This is the famous "ECB penguin"
  problem — encrypt an image in ECB and you can often still make out the
  shape, because repeated pixel blocks produce repeated ciphertext blocks.
- **No authentication.** ECB (and CBC) provide confidentiality only — an
  attacker who can modify ciphertext in transit can often manipulate the
  decrypted plaintext in predictable ways (bit-flipping attacks), and the
  receiver has no way to detect tampering.

**Why `aes_library.py` is safe:** AES-256-**GCM** is an authenticated
encryption mode — it provides both confidentiality and integrity in one
primitive, using a fresh random nonce per message so identical plaintexts
never produce identical ciphertexts. Keys are derived from passwords via
PBKDF2 with a random salt and 390,000 iterations (OWASP's 2023
recommendation), making brute-force password guessing computationally
expensive.

## RSA (`crypto/asymmetric/`)

**`rsa_scratch.py` risks:**
- **Textbook (unpadded) RSA is deterministic.** The same plaintext always
  produces the same ciphertext under a given key, letting an attacker
  build a dictionary of known plaintext→ciphertext pairs, or detect when
  two parties are sending the same message.
- **Textbook RSA is malleable.** Given `c = m^e mod n`, an attacker can
  compute `c' = c * k^e mod n` to get a ciphertext that decrypts to
  `m * k mod n` — without ever knowing the private key. This breaks
  integrity guarantees in subtle, exploitable ways (see: Bleichenbacher's
  attack on PKCS#1 v1.5 padding, and the broader class of padding oracle
  attacks).
- **Small demo key sizes.** The test suite uses 512-bit keys purely for
  test speed — 512-bit RSA has been factorable since the early 2000s. Real
  keys must be ≥ 2048 bits (3072+ for long-term security).

**Why `rsa_library.py` is safe:** **OAEP** padding (for encryption)
randomizes each ciphertext and is provably secure against chosen-ciphertext
attacks under standard assumptions. **PSS** padding (for signatures) is
similarly randomized and resistant to the existential forgery attacks that
affect older PKCS#1 v1.5 signatures. Keys default to 2048 bits.

## Hashing (`crypto/hashing/`)

`sha256_scratch.py` is cryptographically equivalent to `hashlib.sha256`
(verified bit-for-bit in tests) — SHA-256 itself has no known practical
attacks, so the only reason to prefer `hashlib` in production is
**performance** (C vs. pure Python), not security.

The real risk area is in `integrity.py`'s domain — **how hashes are used**:
- **Never hash passwords with a single fast round of SHA-256.** Modern
  GPUs can compute billions of SHA-256 hashes per second, making
  dictionary/brute-force attacks on leaked hash databases fast. PBKDF2
  (used here, with 390k iterations) deliberately makes each guess
  expensive; bcrypt/scrypt/Argon2 do the same with added memory-hardness
  against GPU/ASIC attacks.
- **Always use a per-password random salt.** Without one, identical
  passwords produce identical hashes, and attackers can precompute "rainbow
  tables" of hash→password mappings for common passwords.
- **Always compare MACs/signatures in constant time**
  (`hmac.compare_digest`, used throughout this repo) — a naive `==`
  comparison on bytes short-circuits on the first mismatched byte, letting
  a remote attacker recover a valid MAC one byte at a time by measuring
  response timing.

## The one-sentence summary

**Use `*_library.py` for anything real. Use `*_scratch.py` to understand
why `*_library.py` is built the way it is.**
