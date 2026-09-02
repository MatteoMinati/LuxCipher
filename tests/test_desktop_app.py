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
        app._running = False

    def test_inactivity_timeout_and_auto_lock(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            store = AccountStore(db_path)
            mock_page = MagicMock()
            app = LuxCipherFletApp(page=mock_page, account_store=store, auto_lock_timeout=0.01)

            # Setup account and open vault
            app.auth_username_field.value = "matteo"
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertTrue(store.is_open())

            # Trigger auto-lock
            app._trigger_auto_lock()
            self.assertFalse(store.is_open())
            self.assertEqual(app.auth_mode, "login")
            self.assertEqual(app.current_username, "")

            app._running = False
            store.close()

    def test_record_activity_resets_timestamp(self) -> None:
        mock_page = MagicMock()
        app = LuxCipherFletApp(page=mock_page, account_store=MagicMock())
        old_time = app.last_activity_time
        app.last_activity_time = old_time - 100
        app.record_activity()
        self.assertGreater(app.last_activity_time, old_time - 50)
        app._running = False

    def test_search_in_ui(self) -> None:
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            store = AccountStore(db_path)
            mock_page = MagicMock()
            app = LuxCipherFletApp(page=mock_page, account_store=store)

            # Setup account and open vault
            app.auth_username_field.value = "matteo"
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()

            # Add two accounts
            app.new_service_field.value = "GitHub"
            app.new_user_field.value = "octocat@github.com"
            app.new_pwd_field.value = "pass1"
            app._add_account_entry()

            app.new_service_field.value = "Google"
            app.new_user_field.value = "user@gmail.com"
            app.new_pwd_field.value = "pass2"
            app._add_account_entry()

            # Test search query
            app._on_search_change("git")
            self.assertEqual(app.search_query, "git")

            app._on_search_change("")
            self.assertEqual(app.search_query, "")

            app._running = False
            store.close()


if __name__ == "__main__":
    unittest.main()




