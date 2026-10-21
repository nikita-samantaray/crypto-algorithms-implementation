import hashlib
import unittest

from crypto.hashing import sha256_scratch, integrity


class TestSha256Scratch(unittest.TestCase):
    def test_matches_hashlib_empty(self):
        self.assertEqual(sha256_scratch.sha256(b""), hashlib.sha256(b"").digest())

    def test_matches_hashlib_abc(self):
        self.assertEqual(sha256_scratch.sha256(b"abc"), hashlib.sha256(b"abc").digest())

    def test_matches_hashlib_long_message(self):
        msg = b"The quick brown fox jumps over the lazy dog" * 50
        self.assertEqual(sha256_scratch.sha256(msg), hashlib.sha256(msg).digest())

    def test_matches_hashlib_across_block_boundary(self):
        # exercise padding edge cases around the 56/64-byte boundary
        for length in [55, 56, 57, 63, 64, 65, 119, 120, 121]:
            msg = bytes(range(length % 256)) * (length // max(length % 256, 1) + 1)
            msg = msg[:length]
            with self.subTest(length=length):
                self.assertEqual(sha256_scratch.sha256(msg), hashlib.sha256(msg).digest())

    def test_known_vector_abc(self):
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(sha256_scratch.sha256_hexdigest(b"abc"), expected)


class TestIntegrity(unittest.TestCase):
    def test_hmac_verify_succeeds(self):
        mac = integrity.compute_hmac(b"message", b"secret-key")
        self.assertTrue(integrity.verify_hmac(b"message", b"secret-key", mac))

    def test_hmac_verify_fails_on_tamper(self):
        mac = integrity.compute_hmac(b"message", b"secret-key")
        self.assertFalse(integrity.verify_hmac(b"tampered", b"secret-key", mac))

    def test_hmac_verify_fails_wrong_key(self):
        mac = integrity.compute_hmac(b"message", b"key-a")
        self.assertFalse(integrity.verify_hmac(b"message", b"key-b", mac))

    def test_password_hash_verify(self):
        salt, h = integrity.hash_password("correct horse battery staple")
        self.assertTrue(integrity.verify_password("correct horse battery staple", salt, h))

    def test_password_hash_rejects_wrong_password(self):
        salt, h = integrity.hash_password("right-password")
        self.assertFalse(integrity.verify_password("wrong-password", salt, h))

    def test_encoded_roundtrip(self):
        salt, h = integrity.hash_password("mypassword")
        encoded = integrity.encode_password_hash(salt, h)
        self.assertTrue(integrity.verify_encoded("mypassword", encoded))
        self.assertFalse(integrity.verify_encoded("wrongpassword", encoded))


if __name__ == "__main__":
    unittest.main()
