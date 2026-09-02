from unittest.mock import MagicMock
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from luxcipher.account_store import AccountStore
from luxcipher.desktop_app import LuxCipherFletApp, LuxCipherApp


class DesktopAppTests(unittest.TestCase):
    def test_desktop_app_class_is_importable(self) -> None:
        self.assertIsNotNone(LuxCipherFletApp)
        self.assertIsNotNone(LuxCipherApp)

    def test_flet_app_logic(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            store = AccountStore(db_path)
            mock_page = MagicMock()
            mock_page.controls = []

            app = LuxCipherFletApp(page=mock_page, account_store=store)

            # Initially setup mode since db does not exist
            self.assertEqual(app.auth_mode, "setup")

            # Switch mode
            app._set_auth_mode("login")
            self.assertEqual(app.auth_mode, "login")
            app._set_auth_mode("setup")
            self.assertEqual(app.auth_mode, "setup")

            # Try create account without username
            app.auth_username_field.value = ""
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Create account with username
            app.auth_username_field.value = "matteo"
            app._submit_auth()
            self.assertTrue(store.is_open())
            self.assertEqual(app.current_username, "matteo")
            self.assertEqual(store.get_account_username(), "matteo")

            # Add an account
            app.new_service_field.value = "GitHub"
            app.new_user_field.value = "octocat"
            app.new_pwd_field.value = "token123"
            app._add_account_entry()
            self.assertEqual(len(store.get_all_accounts()), 1)

            # Lock vault
            app._lock_vault()
            self.assertFalse(store.is_open())
            self.assertEqual(app.auth_mode, "login")

            # Try login with wrong password
            app.auth_username_field.value = "matteo"
            app.auth_password_field.value = "WrongPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Try login with wrong username
            app.auth_username_field.value = "wrong_user"
            app.auth_password_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Login with correct credentials
            app.auth_username_field.value = "matteo"
            app.auth_password_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertTrue(store.is_open())
            self.assertEqual(app.current_username, "matteo")

            store.close()

    def test_title_bar_controls_outside_drag_area(self) -> None:
        mock_page = MagicMock()
        app = LuxCipherFletApp(page=mock_page, account_store=MagicMock())
        title_bar = app._build_custom_title_bar()
        self.assertIsNotNone(title_bar)


if __name__ == "__main__":
    unittest.main()

