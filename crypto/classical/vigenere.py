"""
Vigenere Cipher - a polyalphabetic substitution cipher using a repeating
keyword to vary the shift per character, defeating simple frequency
analysis (unlike Caesar). Historically called "le chiffre indechiffrable"
("the indecipherable cipher") until Kasiski/Friedman cryptanalysis broke it
in the 19th century.

Security note: still a classical cipher - breakable via Kasiski examination
(finding repeated ciphertext sequences to estimate key length) followed by
frequency analysis on each key-length subset. Educational use only.
"""

from __future__ import annotations

ALPHABET_SIZE = 26


def _key_stream(key: str, length: int) -> str:
    key = "".join(c for c in key if c.isalpha())
    if not key:
        raise ValueError("Key must contain at least one alphabetic character")
    return "".join(key[i % len(key)] for i in range(length))


def encrypt(plaintext: str, key: str) -> str:
    alpha_positions = [i for i, c in enumerate(plaintext) if c.isalpha()]
    stream = _key_stream(key, len(alpha_positions))

    result = list(plaintext)
    for stream_idx, pos in enumerate(alpha_positions):
        ch = plaintext[pos]
        base = ord("A") if ch.isupper() else ord("a")
        key_char = stream[stream_idx].upper()
        shift = ord(key_char) - ord("A")
        shifted = (ord(ch) - base + shift) % ALPHABET_SIZE
        result[pos] = chr(base + shifted)

    return "".join(result)


def decrypt(ciphertext: str, key: str) -> str:
    alpha_positions = [i for i, c in enumerate(ciphertext) if c.isalpha()]
    stream = _key_stream(key, len(alpha_positions))

    result = list(ciphertext)
    for stream_idx, pos in enumerate(alpha_positions):
        ch = ciphertext[pos]
        base = ord("A") if ch.isupper() else ord("a")
        key_char = stream[stream_idx].upper()
        shift = ord(key_char) - ord("A")
        shifted = (ord(ch) - base - shift) % ALPHABET_SIZE
        result[pos] = chr(base + shifted)

    return "".join(result)


def kasiski_find_repeats(ciphertext: str, min_seq_len: int = 3) -> dict:
    """Finds repeated substrings and the distances between their occurrences
    - the first step of Kasiski examination for estimating key length.
    Returns a mapping of sequence -> list of distances between repeats."""
    clean = "".join(c for c in ciphertext if c.isalpha()).upper()
    positions: dict[str, list[int]] = {}
    for i in range(len(clean) - min_seq_len + 1):
        seq = clean[i : i + min_seq_len]
        positions.setdefault(seq, []).append(i)

    distances = {}
    for seq, pos_list in positions.items():
        if len(pos_list) > 1:
            distances[seq] = [pos_list[j] - pos_list[j - 1] for j in range(1, len(pos_list))]
    return distances
