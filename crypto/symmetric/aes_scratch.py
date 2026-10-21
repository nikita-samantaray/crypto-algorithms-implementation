"""
AES-128 implemented from scratch (educational), following FIPS 197.

Implements the full key schedule, SubBytes, ShiftRows, MixColumns and
AddRoundKey steps over GF(2^8), in ECB mode with PKCS#7 padding.

⚠️  SECURITY WARNING: This is a teaching implementation. It is NOT
constant-time (vulnerable to timing side-channel attacks), uses ECB mode
(which leaks data patterns - see the "ECB penguin" problem), and has not
been audited. NEVER use this for real secrets - use `aes_library.py`
(backed by the audited `cryptography` package) for anything production.
"""

from __future__ import annotations

# --- AES S-Box and inverse S-Box (FIPS 197, Figure 7) ---------------------
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_S_BOX = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

NB = 4  # block size in 32-bit words (always 4 for AES)
NK = 4  # key length in 32-bit words (4 = AES-128)
NR = 10  # number of rounds (10 = AES-128)


def _xtime(a: int) -> int:
    """Multiply by x (i.e. {02}) in GF(2^8) with AES's reduction polynomial."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiplication in GF(2^8), used by MixColumns."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return result


def _key_expansion(key: bytes) -> list[list[int]]:
    """Expands a 16-byte key into NR+1 round keys (each 4 words of 4 bytes)."""
    w = [list(key[4 * i : 4 * i + 4]) for i in range(NK)]

    for i in range(NK, NB * (NR + 1)):
        temp = list(w[i - 1])
        if i % NK == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [S_BOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // NK - 1]
        w.append([w[i - NK][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(NR + 1):
        round_keys.append([byte for word in w[4 * r : 4 * r + 4] for byte in word])
    return round_keys


def _bytes_to_state(block: bytes) -> list[list[int]]:
    """Column-major 4x4 state matrix, per FIPS 197."""
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _add_round_key(state, round_key: list[int]):
    rk = _bytes_to_state(bytes(round_key))
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk[r][c]


def _sub_bytes(state, box=S_BOX):
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def _mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        state[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        state[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        state[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)


def _inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        state[1][c] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        state[2][c] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        state[3][c] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypts a single 16-byte block with a 16-byte key (AES-128)."""
    assert len(block) == 16 and len(key) == 16
    round_keys = _key_expansion(key)
    state = _bytes_to_state(block)

    _add_round_key(state, round_keys[0])
    for rnd in range(1, NR):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[NR])

    return _state_to_bytes(state)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    assert len(block) == 16 and len(key) == 16
    round_keys = _key_expansion(key)
    state = _bytes_to_state(block)

    _add_round_key(state, round_keys[NR])
    for rnd in range(NR - 1, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes_inv_wrapper(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes_inv_wrapper(state)
    _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


def _sub_bytes_inv_wrapper(state):
    _sub_bytes(state, box=INV_S_BOX)


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-ECB with PKCS#7 padding.

    ⚠️ ECB mode is included ONLY to demonstrate the raw block cipher end to
    end. It leaks patterns in the plaintext (identical blocks -> identical
    ciphertext blocks) and should never be used in real systems. See
    `aes_library.encrypt_gcm` for a secure, authenticated mode.
    """
    padded = _pkcs7_pad(plaintext)
    return b"".join(
        encrypt_block(padded[i : i + 16], key) for i in range(0, len(padded), 16)
    )


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")
    plain_padded = b"".join(
        decrypt_block(ciphertext[i : i + 16], key) for i in range(0, len(ciphertext), 16)
    )
    return _pkcs7_unpad(plain_padded)
