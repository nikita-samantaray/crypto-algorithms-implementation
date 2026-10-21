"""
Caesar Cipher - the simplest substitution cipher, shifting each letter by
a fixed amount in the alphabet. Included for historical/educational context
and as a baseline for understanding why modern cryptography exists.

Security note: trivially broken by brute force (only 25 possible shifts)
or frequency analysis. Never use for anything that needs real secrecy.
"""

from __future__ import annotations

ALPHABET_SIZE = 26


def encrypt(plaintext: str, shift: int) -> str:
    """Shifts each alphabetic character forward by `shift` positions,
    preserving case and passing non-alphabetic characters through unchanged."""
    result = []
    for ch in plaintext:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shifted = (ord(ch) - base + shift) % ALPHABET_SIZE
            result.append(chr(base + shifted))
        else:
            result.append(ch)
    return "".join(result)


def decrypt(ciphertext: str, shift: int) -> str:
    return encrypt(ciphertext, -shift)


def brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """Tries all 26 possible shifts - demonstrates why Caesar is insecure."""
    return [(shift, decrypt(ciphertext, shift)) for shift in range(ALPHABET_SIZE)]


def frequency_analysis_guess(ciphertext: str) -> tuple[int, str]:
    """Guesses the shift by assuming the most frequent letter in the
    ciphertext maps to 'e' (the most common English letter). A classic
    cryptanalysis technique against Caesar/substitution ciphers."""
    from collections import Counter

    letters = [c.lower() for c in ciphertext if c.isalpha()]
    if not letters:
        return 0, ciphertext
    most_common_letter, _ = Counter(letters).most_common(1)[0]
    guessed_shift = (ord(most_common_letter) - ord("e")) % ALPHABET_SIZE
    return guessed_shift, decrypt(ciphertext, guessed_shift)
