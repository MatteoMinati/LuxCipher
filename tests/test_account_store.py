from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from luxcipher.account_store import AccountStore, AccountStoreError
from luxcipher.auth import derive_master_key


class AccountStoreTests(unittest.TestCase):
    def test_open_add_and_get_accounts(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x10" * 16
            key = derive_master_key("MasterPass123!", salt=salt)

            store = AccountStore(db_path)
            self.assertFalse(store.is_open())

            store.open(key)
            self.assertTrue(store.is_open())
            self.assertTrue(store.exists())

            store.add_account("GitHub", "octocat", "super_secret_github_token")
            store.add_account("Google", "user@gmail.com", "google_pass_123")

            accounts = store.get_all_accounts()
            self.assertEqual(len(accounts), 2)
            self.assertEqual(accounts[0][1:], ("GitHub", "octocat", "super_secret_github_token"))
            self.assertEqual(accounts[1][1:], ("Google", "user@gmail.com", "google_pass_123"))

            store.close()
            self.assertFalse(store.is_open())

    def test_reopen_with_correct_key(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x20" * 16
            key = derive_master_key("CorrectPassword456!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                store.add_account("ProtonMail", "contact@luxcipher.org", "proton_secret")

            with AccountStore(db_path) as store:
                store.open(key)
                accounts = store.get_all_accounts()
                self.assertEqual(len(accounts), 1)
                self.assertEqual(accounts[0][1:], ("ProtonMail", "contact@luxcipher.org", "proton_secret"))

    def test_open_with_wrong_key_raises_value_error(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x30" * 16
            correct_key = derive_master_key("RealPassword789!", salt=salt)
            wrong_key = derive_master_key("WrongPassword000!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(correct_key)
                store.add_account("Bank", "user_bank", "bank_pin_1234")

            # Opening with wrong key must raise ValueError with "Master Password errata"
            store_wrong = AccountStore(db_path)
            with self.assertRaises(ValueError) as context:
                store_wrong.open(wrong_key)

            self.assertEqual(str(context.exception), "Master Password errata")
            self.assertFalse(store_wrong.is_open())

    def test_database_is_encrypted_on_disk(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x40" * 16
            key = derive_master_key("DiskEncryptionTest1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                store.add_account("ConfidentialService", "classified_user", "classified_secret_password")

            # Read raw bytes directly from the database file on disk
            raw_bytes = db_path.read_bytes()
            self.assertNotIn(b"SQLite format 3", raw_bytes)
            self.assertNotIn(b"ConfidentialService", raw_bytes)
            self.assertNotIn(b"classified_user", raw_bytes)
            self.assertNotIn(b"classified_secret_password", raw_bytes)

    def test_operations_without_open_raise_error(self) -> None:
        store = AccountStore("some_vault.db")
        with self.assertRaises(AccountStoreError):
            store.add_account("Test", "User", "Pass")

        with self.assertRaises(AccountStoreError):
            store.get_all_accounts()

        with self.assertRaises(AccountStoreError):
            store.set_account_username("matteo")

        with self.assertRaises(AccountStoreError):
            store.get_account_username()

    def test_set_and_get_account_username(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x50" * 16
            key = derive_master_key("PassWithUsername1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                self.assertIsNone(store.get_account_username())

                store.set_account_username("matteominati")
                self.assertEqual(store.get_account_username(), "matteominati")

            with AccountStore(db_path) as store:
                store.open(key)
                self.assertEqual(store.get_account_username(), "matteominati")

    def test_search_accounts(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x60" * 16
            key = derive_master_key("SearchTestPass1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                store.add_account("GitHub", "octocat@github.com", "gh_pass")
                store.add_account("Google", "matteo@gmail.com", "google_pass")
                store.add_account("Netflix", "matteo@netflix.com", "netflix_pass")

                # Search by service name
                res_gh = store.search_accounts("git")
                self.assertEqual(len(res_gh), 1)
                self.assertEqual(res_gh[0][1], "GitHub")

                # Search by username / email
                res_matteo = store.search_accounts("matteo")
                self.assertEqual(len(res_matteo), 2)

                # Search with empty query returns all
                res_all = store.search_accounts("")
                self.assertEqual(len(res_all), 3)

                # Search with non-matching query
                res_none = store.search_accounts("nonexistent")
                self.assertEqual(len(res_none), 0)


if __name__ == "__main__":
    unittest.main()


