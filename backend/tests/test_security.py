import unittest

from app.ratelimit import RateLimiter
from app.security import hash_password, hash_token, new_token, verify_password


class PasswordTests(unittest.TestCase):
    def test_roundtrip_and_wrong_password(self):
        stored = hash_password("correct horse")
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertTrue(verify_password("correct horse", stored))
        self.assertFalse(verify_password("wrong", stored))

    def test_salt_makes_hashes_differ(self):
        self.assertNotEqual(hash_password("same"), hash_password("same"))

    def test_malformed_stored_hash_is_rejected_not_raised(self):
        for bad in ("", "x", "scrypt$1$2", "bcrypt$a$b$c$d$e", "scrypt$a$b$c$d$e"):
            self.assertFalse(verify_password("x", bad))

    def test_unicode_password(self):
        stored = hash_password("sênha-çãõ-密码")
        self.assertTrue(verify_password("sênha-çãõ-密码", stored))


class TokenTests(unittest.TestCase):
    def test_tokens_are_unique_and_hash_is_stable(self):
        a, b = new_token(), new_token()
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 40)
        self.assertEqual(hash_token(a), hash_token(a))
        self.assertNotEqual(hash_token(a), a)


class RateLimiterTests(unittest.TestCase):
    def test_blocks_after_limit_and_recovers_after_window(self):
        now = [0.0]
        limiter = RateLimiter(3, 10, clock=lambda: now[0])
        self.assertEqual([limiter.hit("k") for _ in range(4)], [True, True, True, False])
        self.assertTrue(limiter.hit("other"))
        now[0] = 11.0
        self.assertTrue(limiter.hit("k"))

    def test_reset_clears_key(self):
        limiter = RateLimiter(1, 60)
        self.assertTrue(limiter.hit("k"))
        self.assertFalse(limiter.hit("k"))
        limiter.reset("k")
        self.assertTrue(limiter.hit("k"))


if __name__ == "__main__":
    unittest.main()
