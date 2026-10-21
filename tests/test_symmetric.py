import unittest

from crypto.symmetric import aes_scratch, aes_library


class TestAesScratch(unittest.TestCase):
    def test_fips197_official_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes_scratch.encrypt_block(plaintext, key), expected)

    def test_block_roundtrip(self):
        key = bytes(range(16))
        block = bytes(range(16, 32))
        ct = aes_scratch.encrypt_block(block, key)
        self.assertEqual(aes_scratch.decrypt_block(ct, key), block)

    def test_ecb_multiblock_roundtrip(self):
        key = b"0123456789abcdef"
        msg = b"This message spans multiple 16-byte AES blocks for a thorough test."
        ct = aes_scratch.encrypt_ecb(msg, key)
        self.assertEqual(len(ct) % 16, 0)
        self.assertEqual(aes_scratch.decrypt_ecb(ct, key), msg)

    def test_ecb_rejects_tampered_padding(self):
        key = b"0123456789abcdef"
        ct = bytearray(aes_scratch.encrypt_ecb(b"short", key))
        ct[-1] ^= 0xFF  # corrupt the padding byte
        with self.assertRaises(ValueError):
            aes_scratch.decrypt_ecb(bytes(ct), key)


class TestAesLibrary(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        payload = aes_library.encrypt(b"top secret", "my-password")
        self.assertEqual(aes_library.decrypt(payload, "my-password"), b"top secret")

    def test_wrong_password_rejected(self):
        payload = aes_library.encrypt(b"data", "right-password")
        with self.assertRaises(Exception):
            aes_library.decrypt(payload, "wrong-password")

    def test_to_bytes_roundtrip(self):
        blob = aes_library.encrypt_to_bytes(b"blob data", "pw")
        self.assertEqual(aes_library.decrypt_from_bytes(blob, "pw"), b"blob data")

    def test_different_nonce_each_call(self):
        p1 = aes_library.encrypt(b"same message", "pw")
        p2 = aes_library.encrypt(b"same message", "pw")
        self.assertNotEqual(p1.nonce, p2.nonce)
        self.assertNotEqual(p1.ciphertext, p2.ciphertext)


if __name__ == "__main__":
    unittest.main()
