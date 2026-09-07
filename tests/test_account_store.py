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
            store.add_account("Google", "user@example.com", "google_pass_123")

            accounts = store.get_all_accounts()
            self.assertEqual(len(accounts), 2)
            self.assertEqual(accounts[0][1:4], ("GitHub", "octocat", "super_secret_github_token"))
            self.assertEqual(accounts[1][1:4], ("Google", "user@example.com", "google_pass_123"))

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
                self.assertEqual(accounts[0][1:4], ("ProtonMail", "contact@luxcipher.org", "proton_secret"))

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
            store.set_account_username("test_user")

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

                store.set_account_username("vault_owner")
                self.assertEqual(store.get_account_username(), "vault_owner")

            with AccountStore(db_path) as store:
                store.open(key)
                self.assertEqual(store.get_account_username(), "vault_owner")

    def test_search_accounts(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x60" * 16
            key = derive_master_key("SearchTestPass1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                store.add_account("GitHub", "octocat@example.org", "gh_pass")
                store.add_account("Google", "alice@example.com", "google_pass")
                store.add_account("Netflix", "alice@example.net", "netflix_pass")

                # Search by service name
                res_gh = store.search_accounts("git")
                self.assertEqual(len(res_gh), 1)
                self.assertEqual(res_gh[0][1], "GitHub")

                # Search by username / email
                res_alice = store.search_accounts("alice")
                self.assertEqual(len(res_alice), 2)

                # Search with empty query returns all
                res_all = store.search_accounts("")
                self.assertEqual(len(res_all), 3)

                # Search with non-matching query
                res_none = store.search_accounts("nonexistent")
                self.assertEqual(len(res_none), 0)

    def test_search_treats_like_wildcards_as_literal_text(self) -> None:
        # Regression: "%" and "_" reached LIKE unescaped, so searching for either
        # returned every credential instead of the ones containing them.
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"p" * 16
            key = derive_master_key("WildcardTestPass1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                store.add_account("Sconto 100%", "a@example.com", "p1")
                store.add_account("under_score", "b@example.com", "p2")
                store.add_account("Netflix", "c@example.com", "p3")

                self.assertEqual(len(store.search_accounts("%")), 1)
                self.assertEqual(len(store.search_accounts("100%")), 1)
                self.assertEqual(len(store.search_accounts("_")), 1)
                self.assertEqual(len(store.search_accounts("net")), 1)
                self.assertEqual(len(store.search_accounts("%%%")), 0)

    def test_update_and_delete_a_credential(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x80" * 16
            key = derive_master_key("CrudTestPassword1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                account_id = store.add_account("GitHub", "octocat", "old_token")
                other_id = store.add_account("Amazon", "buyer", "other")

                store.update_account(account_id, "GitHub Enterprise", "octocat", "new_token")
                row = store.get_account(account_id)
                self.assertEqual(row[1:4], ("GitHub Enterprise", "octocat", "new_token"))

                store.delete_account(account_id)
                self.assertIsNone(store.get_account(account_id))
                self.assertEqual(store.count_accounts(), 1)
                self.assertIsNotNone(store.get_account(other_id))

                with self.assertRaises(AccountStoreError):
                    store.update_account(account_id, "Gone", "x", "y")
                with self.assertRaises(AccountStoreError):
                    store.delete_account(account_id)

    def test_credentials_carry_timestamps(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\x90" * 16
            key = derive_master_key("TimestampPassword1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                account_id = store.add_account("GitHub", "octocat", "token")
                created, updated = store.get_account(account_id)[4:6]
                self.assertTrue(created)
                self.assertEqual(created, updated)
                self.assertTrue(created.endswith("Z"))

    def test_rejects_empty_service_or_password(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            key = derive_master_key("EmptyFieldPass1!", salt=b"\xa0" * 16)

            with AccountStore(db_path) as store:
                store.open(key)
                with self.assertRaises(ValueError):
                    store.add_account("   ", "user", "pass")
                with self.assertRaises(ValueError):
                    store.add_account("Service", "user", "")
                # A blank username is allowed: not every credential has one.
                self.assertIsNotNone(store.add_account("Service", "", "pass"))

    def test_change_master_key_reencrypts_the_vault(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            salt = b"\xb0" * 16
            old_key = derive_master_key("OriginalMasterPass1!", salt=salt)
            new_key = derive_master_key("ReplacementMasterPass1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(old_key)
                store.add_account("GitHub", "octocat", "token")
                store.change_master_key(new_key)

            # The old key no longer opens it, the new one does, data intact.
            with self.assertRaises(ValueError):
                AccountStore(db_path).open(old_key)

            with AccountStore(db_path) as store:
                store.open(new_key)
                self.assertEqual(store.count_accounts(), 1)
                self.assertEqual(store.get_all_accounts()[0][1], "GitHub")

    def test_backup_copies_both_database_and_salt(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            db_path = root / "vault.db"
            salt = b"\xc0" * 16
            (root / "vault.salt").write_bytes(salt)
            key = derive_master_key("BackupTestPassword1!", salt=salt)

            with AccountStore(db_path) as store:
                store.open(key)
                store.add_account("GitHub", "octocat", "token")
                backup = store.backup_to(root / "backups")

            # A database without its salt could never be opened again.
            self.assertTrue((backup / "vault.db").is_file())
            self.assertTrue((backup / "vault.salt").is_file())
            self.assertEqual((backup / "vault.salt").read_bytes(), salt)

            with AccountStore(backup / "vault.db") as restored:
                restored.open(key)
                self.assertEqual(restored.get_all_accounts()[0][1:4], ("GitHub", "octocat", "token"))

    def test_opens_and_migrates_a_schema_v1_vault(self) -> None:
        from sqlcipher3 import dbapi2 as sqlcipher

        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            key = derive_master_key("LegacyVaultPassword1!", salt=b"\xd0" * 16)

            # Build a vault the way version 1 wrote them: no timestamp columns.
            legacy = sqlcipher.connect(str(db_path))
            cursor = legacy.cursor()
            cursor.execute("PRAGMA key = \"x'%s'\";" % key.hex())
            cursor.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            cursor.execute(
                """CREATE TABLE accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                );"""
            )
            cursor.execute(
                "INSERT INTO accounts (service, username, password) VALUES ('Legacy', 'u', 's');"
            )
            cursor.execute("INSERT INTO metadata VALUES ('username', 'test_user');")
            legacy.commit()
            legacy.close()

            with AccountStore(db_path) as store:
                store.open(key)
                self.assertEqual(store.get_account_username(), "test_user")
                row = store.get_all_accounts()[0]
                self.assertEqual(row[1:4], ("Legacy", "u", "s"))
                # Migrated rows have empty stamps rather than invented ones.
                self.assertEqual(row[4], "")

                store.update_account(row[0], "Legacy", "u", "rotated")
                self.assertTrue(store.get_account(row[0])[5])


if __name__ == "__main__":
    unittest.main()


