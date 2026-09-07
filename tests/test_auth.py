from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from luxcipher.auth import (
    MIN_MASTER_PASSWORD_LENGTH,
    derive_master_key,
    get_or_create_salt,
    is_master_password_strong_enough,
    normalize_username,
)


class CredentialRuleTests(unittest.TestCase):
    def test_normalize_username_trims_and_accepts_allowed_characters(self) -> None:
        self.assertEqual(normalize_username(" test_user "), "test_user")
        self.assertEqual(normalize_username("a.b-c_1"), "a.b-c_1")

    def test_normalize_username_rejects_invalid_usernames(self) -> None:
        for invalid in ("ab", "", "test_user@example.com", "with space", "x" * 65):
            with self.subTest(username=invalid):
                with self.assertRaises(ValueError):
                    normalize_username(invalid)

    def test_normalize_username_requires_a_string(self) -> None:
        with self.assertRaises(TypeError):
            normalize_username(1234)  # type: ignore[arg-type]

    def test_master_password_strength_policy(self) -> None:
        self.assertTrue(is_master_password_strong_enough("x" * MIN_MASTER_PASSWORD_LENGTH))
        self.assertFalse(is_master_password_strong_enough("x" * (MIN_MASTER_PASSWORD_LENGTH - 1)))
        self.assertFalse(is_master_password_strong_enough(" " * MIN_MASTER_PASSWORD_LENGTH))
        self.assertFalse(is_master_password_strong_enough(""))
        self.assertFalse(is_master_password_strong_enough(None))  # type: ignore[arg-type]


class Argon2MasterKeyTests(unittest.TestCase):
    def test_get_or_create_salt_creates_and_persists_16_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            salt_file = Path(directory) / "vault.salt"
            self.assertFalse(salt_file.exists())

            salt1 = get_or_create_salt(salt_file)
            self.assertEqual(len(salt1), 16)
            self.assertTrue(salt_file.is_file())
            self.assertEqual(salt_file.read_bytes(), salt1)

            # Second call should load existing salt
            salt2 = get_or_create_salt(salt_file)
            self.assertEqual(salt1, salt2)

    def test_get_or_create_salt_refuses_to_replace_a_corrupted_salt(self) -> None:
        # Regression: a truncated salt file used to be silently regenerated,
        # which made an existing vault permanently undecryptable.
        with TemporaryDirectory() as directory:
            salt_file = Path(directory) / "vault.salt"
            original = get_or_create_salt(salt_file)
            truncated = original[:8]
            salt_file.write_bytes(truncated)

            with self.assertRaises(ValueError):
                get_or_create_salt(salt_file)

            self.assertEqual(salt_file.read_bytes(), truncated)

    def test_derive_master_key_returns_32_bytes_consistently(self) -> None:
        salt = b"\x01" * 16
        key1 = derive_master_key("my_secure_password", salt=salt)
        key2 = derive_master_key("my_secure_password", salt=salt)

        self.assertIsInstance(key1, bytes)
        self.assertEqual(len(key1), 32)
        self.assertEqual(key1, key2)

        # Different password produces different key
        key3 = derive_master_key("different_password", salt=salt)
        self.assertNotEqual(key1, key3)

        # Different salt produces different key
        diff_salt = b"\x02" * 16
        key4 = derive_master_key("my_secure_password", salt=diff_salt)
        self.assertNotEqual(key1, key4)

    def test_derive_master_key_validations(self) -> None:
        with self.assertRaises(TypeError):
            derive_master_key(12345)  # type: ignore

        with self.assertRaises(TypeError):
            derive_master_key("password", salt="not_bytes")  # type: ignore


if __name__ == "__main__":
    unittest.main()
