import unittest

from crypto.asymmetric import rsa_scratch, rsa_library


class TestRsaScratch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Small key size purely to keep test runtime fast; real usage
        # should use >= 2048 bits (see rsa_library tests below).
        cls.keypair = rsa_scratch.generate_keypair(bits=512)

    def test_encrypt_decrypt_roundtrip(self):
        msg = b"hello rsa"
        ct = rsa_scratch.encrypt_bytes(msg, self.keypair.public)
        pt = rsa_scratch.decrypt_bytes(ct, self.keypair.private)
        self.assertEqual(pt, msg)

    def test_signature_verifies(self):
        msg = b"sign this message"
        sig = rsa_scratch.sign(msg, self.keypair.private)
        self.assertTrue(rsa_scratch.verify(msg, sig, self.keypair.public))

    def test_tampered_message_fails_verification(self):
        msg = b"original message"
        sig = rsa_scratch.sign(msg, self.keypair.private)
        self.assertFalse(rsa_scratch.verify(b"tampered message", sig, self.keypair.public))

    def test_public_private_math_relationship(self):
        # m^(e*d) mod n == m, the core RSA correctness property
        m = 42
        c = rsa_scratch.encrypt_int(m, self.keypair.public)
        recovered = rsa_scratch.decrypt_int(c, self.keypair.private)
        self.assertEqual(recovered, m)


class TestRsaLibrary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = rsa_library.generate_keypair(key_size=2048)

    def test_encrypt_decrypt_roundtrip(self):
        ct = rsa_library.encrypt(b"hello", self.public_key)
        self.assertEqual(rsa_library.decrypt(ct, self.private_key), b"hello")

    def test_signature_verifies(self):
        sig = rsa_library.sign(b"message", self.private_key)
        self.assertTrue(rsa_library.verify(b"message", sig, self.public_key))

    def test_tampered_signature_rejected(self):
        sig = rsa_library.sign(b"message", self.private_key)
        self.assertFalse(rsa_library.verify(b"different message", sig, self.public_key))

    def test_serialization_roundtrip(self):
        pem = rsa_library.serialize_private_key(self.private_key)
        self.assertIn(b"BEGIN PRIVATE KEY", pem)
        pub_pem = rsa_library.serialize_public_key(self.public_key)
        self.assertIn(b"BEGIN PUBLIC KEY", pub_pem)


if __name__ == "__main__":
    unittest.main()
