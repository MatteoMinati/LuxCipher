from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from luxcipher.account_store import AccountStore
from luxcipher.desktop_app import LuxCipherApp


class DesktopAppTests(unittest.TestCase):
    def test_desktop_app_class_is_importable(self) -> None:
        self.assertIsNotNone(LuxCipherApp)

    def test_desktop_app_initializes_and_switches_modes(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            store = AccountStore(db_path)
            app = LuxCipherApp(account_store=store)
            app.withdraw()  # do not show GUI window during tests

            try:
                # Initially setup screen because db doesn't exist
                self.assertFalse(store.exists())

                # Can switch explicitly to login screen
                app._show_auth_screen("login")

                # Can switch back to setup screen
                app._show_auth_screen("setup")

                # Try creating without username
                app.setup_username.set("")
                app.setup_master_password.set("MySuperPassword123!")
                app.setup_confirm_password.set("MySuperPassword123!")
                app._create_account()
                self.assertFalse(store.is_open())
                self.assertEqual(app.auth_status.get(), "Inserisci un nome utente")

                # Create account with username
                app.setup_username.set("matteo")
                app._create_account()

                self.assertTrue(store.is_open())
                self.assertTrue(store.exists())
                self.assertEqual(app.current_username.get(), "matteo")
                self.assertEqual(store.get_account_username(), "matteo")

                # Add an account entry via GUI methods
                app.new_service.set("GitHub")
                app.new_username.set("octocat")
                app.new_password.set("token123")
                app._add_account()

                self.assertEqual(len(store.get_all_accounts()), 1)

                # Lock the vault
                app._lock()
                self.assertFalse(store.is_open())

                # Try login with wrong password
                app.login_username.set("matteo")
                app.login_master_password.set("WrongPassword123!")
                app._unlock()
                self.assertFalse(store.is_open())
                self.assertEqual(app.auth_status.get(), "Master Password errata")

                # Try login with wrong username
                app.login_username.set("wrong_user")
                app.login_master_password.set("MySuperPassword123!")
                app._unlock()
                self.assertFalse(store.is_open())
                self.assertEqual(app.auth_status.get(), "Nome Utente o Master Password errati")

                # Login with correct username and password
                app.login_username.set("matteo")
                app.login_master_password.set("MySuperPassword123!")
                app._unlock()
                self.assertTrue(store.is_open())
                self.assertEqual(app.current_username.get(), "matteo")

            finally:
                store.close()
                app.destroy()


if __name__ == "__main__":
    unittest.main()
