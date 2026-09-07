from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from luxcipher.auth import (
    ACCOUNT_SCHEMA_VERSION,
    MIN_MASTER_PASSWORD_LENGTH,
    LocalAccount,
    ScryptParameters,
    derive_master_key,
    get_or_create_salt,
)



MASTER_PASSWORD = "correct horse battery staple"


def fast_kdf() -> ScryptParameters:
    return ScryptParameters.create(n=2**10, maxmem=16 * 1024 * 1024)


class LocalAccountTests(unittest.TestCase):
    def test_creates_local_account_that_verifies_master_password(self) -> None:
        account = LocalAccount.create(
            username=" test_user ",
            master_password=MASTER_PASSWORD,
            kdf=fast_kdf(),
        )

        self.assertEqual(account.username, "test_user")
        self.assertTrue(account.verify_master_password(MASTER_PASSWORD))
        self.assertFalse(account.verify_master_password("wrong password"))
        self.assertIsNotNone(account.created_at.tzinfo)
        self.assertIsNotNone(account.updated_at.tzinfo)

    def test_serialized_account_does_not_include_master_password(self) -> None:
        account = LocalAccount.create(
            username="test_user",
            master_password=MASTER_PASSWORD,
            kdf=fast_kdf(),
        )

        serialized = account.to_dict()

        self.assertNotIn(MASTER_PASSWORD, str(serialized))
        self.assertIn("passwordVerifier", serialized)
        self.assertIn("kdf", serialized)

    def test_account_round_trips_through_dictionary(self) -> None:
        account = LocalAccount.create(
            username="test_user",
            master_password=MASTER_PASSWORD,
            kdf=fast_kdf(),
        )

        restored = LocalAccount.from_dict(account.to_dict())

        self.assertEqual(restored, account)
        self.assertTrue(restored.verify_master_password(MASTER_PASSWORD))

    def test_same_password_uses_different_salt_and_verifier(self) -> None:
        first = LocalAccount.create(
            username="test_user",
            master_password=MASTER_PASSWORD,
            kdf=fast_kdf(),
        )
        second = LocalAccount.create(
            username="test_user",
            master_password=MASTER_PASSWORD,
            kdf=fast_kdf(),
        )

        self.assertNotEqual(first.kdf.salt, second.kdf.salt)
        self.assertNotEqual(first.password_verifier, second.password_verifier)

    def test_rejects_weak_master_password(self) -> None:
        with self.assertRaises(ValueError):
            LocalAccount.create(
                username="test_user",
                master_password="x" * (MIN_MASTER_PASSWORD_LENGTH - 1),
                kdf=fast_kdf(),
            )

        with self.assertRaises(ValueError):
            LocalAccount.create(
                username="test_user",
                master_password=" " * MIN_MASTER_PASSWORD_LENGTH,
                kdf=fast_kdf(),
            )

    def test_rejects_invalid_username(self) -> None:
        with self.assertRaises(ValueError):
            LocalAccount.create(
                username="ma",
                master_password=MASTER_PASSWORD,
                kdf=fast_kdf(),
            )

        with self.assertRaises(ValueError):
            LocalAccount.create(
                username="test_user@example.com",
                master_password=MASTER_PASSWORD,
                kdf=fast_kdf(),
            )

    def test_rejects_unsupported_account_schema_version(self) -> None:
        account = LocalAccount.create(
            username="test_user",
            master_password=MASTER_PASSWORD,
            kdf=fast_kdf(),
        )
        data = account.to_dict()
        data["schemaVersion"] = ACCOUNT_SCHEMA_VERSION + 1

        with self.assertRaises(ValueError):
            LocalAccount.from_dict(data)

    def test_rejects_unsupported_kdf(self) -> None:
        kdf_data = fast_kdf().to_dict()
        kdf_data["name"] = "pbkdf2"

        with self.assertRaises(ValueError):
            ScryptParameters.from_dict(kdf_data)

    def test_rejects_tampered_scrypt_parameters(self) -> None:
        kdf_data = fast_kdf().to_dict()
        kdf_data["n"] = 2**20

        with self.assertRaises(ValueError):
            ScryptParameters.from_dict(kdf_data)

        kdf_data = fast_kdf().to_dict()
        kdf_data["n"] = 2**8

        with self.assertRaises(ValueError):
            ScryptParameters.from_dict(kdf_data)

        kdf_data = fast_kdf().to_dict()
        kdf_data["maxmem"] = 1

        with self.assertRaises(ValueError):
            ScryptParameters.from_dict(kdf_data)

    def test_rejects_invalid_base64_salt(self) -> None:
        kdf_data = fast_kdf().to_dict()
        kdf_data["salt"] = "not valid base64!"

        with self.assertRaises(ValueError):
            ScryptParameters.from_dict(kdf_data)


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

