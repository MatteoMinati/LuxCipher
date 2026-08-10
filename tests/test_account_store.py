from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from luxcipher.account_store import AccountStore, AccountStoreError
from luxcipher.auth import LocalAccount, ScryptParameters


MASTER_PASSWORD = "correct horse battery staple"


def fast_account(username: str = "matteo") -> LocalAccount:
    return LocalAccount.create(
        username=username,
        master_password=MASTER_PASSWORD,
        kdf=ScryptParameters.create(n=2**10, maxmem=16 * 1024 * 1024),
    )


class AccountStoreTests(unittest.TestCase):
    def test_saves_and_loads_local_account(self) -> None:
        with TemporaryDirectory() as directory:
            store = AccountStore(Path(directory) / "account.json")
            account = fast_account()

            store.save(account)
            restored = store.load()

            self.assertEqual(restored, account)
            self.assertTrue(restored.verify_master_password(MASTER_PASSWORD))

    def test_reports_missing_account(self) -> None:
        with TemporaryDirectory() as directory:
            store = AccountStore(Path(directory) / "missing.json")

            with self.assertRaises(AccountStoreError):
                store.load()

    def test_reports_invalid_account_metadata(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            path.write_text("{not json", encoding="utf-8")
            store = AccountStore(path)

            with self.assertRaises(AccountStoreError):
                store.load()

    def test_serialized_file_does_not_include_master_password(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "account.json"
            store = AccountStore(path)

            store.save(fast_account())

            self.assertNotIn(MASTER_PASSWORD, path.read_text(encoding="utf-8"))

    def test_does_not_overwrite_existing_account_by_default(self) -> None:
        with TemporaryDirectory() as directory:
            store = AccountStore(Path(directory) / "account.json")
            store.save(fast_account("matteo"))

            with self.assertRaises(AccountStoreError):
                store.save(fast_account("other-user"))

            self.assertEqual(store.load().username, "matteo")


if __name__ == "__main__":
    unittest.main()
