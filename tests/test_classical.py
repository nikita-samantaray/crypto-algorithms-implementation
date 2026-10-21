import unittest

from crypto.classical import caesar, vigenere


class TestCaesar(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        pt = "Attack at Dawn"
        ct = caesar.encrypt(pt, 3)
        self.assertEqual(caesar.decrypt(ct, 3), pt)

    def test_known_vector(self):
        self.assertEqual(caesar.encrypt("Attack at Dawn", 3), "Dwwdfn dw Gdzq")

    def test_non_alpha_unchanged(self):
        self.assertEqual(caesar.encrypt("Hi! 123", 1), "Ij! 123")

    def test_brute_force_finds_correct_shift(self):
        pt = "THE QUICK BROWN FOX"
        ct = caesar.encrypt(pt, 7)
        results = dict(caesar.brute_force(ct))
        self.assertEqual(results[7], pt)


class TestVigenere(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        pt = "Attack at Dawn"
        ct = vigenere.encrypt(pt, "LEMON")
        self.assertEqual(vigenere.decrypt(ct, "LEMON"), pt)

    def test_known_vector(self):
        # Classic textbook example
        self.assertEqual(vigenere.encrypt("Attack at Dawn", "LEMON"), "Lxfopv ef Rnhr")

    def test_kasiski_finds_repeats(self):
        ct = vigenere.encrypt("THE SUN AND THE MOON AND THE STARS" * 2, "KEY")
        repeats = vigenere.kasiski_find_repeats(ct, min_seq_len=4)
        self.assertTrue(len(repeats) > 0)


if __name__ == "__main__":
    unittest.main()
