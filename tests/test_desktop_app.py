from unittest.mock import MagicMock
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import flet as ft

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
            app.auth_username_field.value = "test_user"
            app._submit_auth()
            self.assertTrue(store.is_open())
            self.assertEqual(app.current_username, "test_user")
            self.assertEqual(store.get_account_username(), "test_user")

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
            app.auth_username_field.value = "test_user"
            app.auth_password_field.value = "WrongPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Try login with wrong username
            app.auth_username_field.value = "wrong_user"
            app.auth_password_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Login with correct credentials
            app.auth_username_field.value = "test_user"
            app.auth_password_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertTrue(store.is_open())
            self.assertEqual(app.current_username, "test_user")

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
            app.auth_username_field.value = "test_user"
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
            app.auth_username_field.value = "test_user"
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()

            # Add two accounts
            app.new_service_field.value = "GitHub"
            app.new_user_field.value = "octocat@example.org"
            app.new_pwd_field.value = "pass1"
            app._add_account_entry()

            app.new_service_field.value = "Google"
            app.new_user_field.value = "user@example.com"
            app.new_pwd_field.value = "pass2"
            app._add_account_entry()

            # Test search query
            app._on_search_change("git")
            self.assertEqual(app.search_query, "git")

            app._on_search_change("")
            self.assertEqual(app.search_query, "")

            app._running = False
            store.close()

    def test_generator_controls_sync_and_strength(self) -> None:
        mock_page = MagicMock()
        app = LuxCipherFletApp(page=mock_page, account_store=MagicMock())

        # Test slider change syncs length input and updates pwd
        app._on_length_slider_change(28)
        self.assertEqual(app.gen_length, 28)
        self.assertEqual(app.gen_length_input.value, "28")
        self.assertEqual(len(app.generated_pwd_value), 28)
        self.assertEqual(app.gen_strength_label.value, "Molto Forte")

        # Test length input change syncs slider
        app._on_length_input_change("14")
        self.assertEqual(app.gen_length, 14)
        self.assertEqual(app.gen_slider.value, 14.0)
        self.assertEqual(len(app.generated_pwd_value), 14)

        # Test option toggling
        app._toggle_gen_opt("symbols", False)
        self.assertFalse(app.gen_symbols)

        # Test regenerate
        app._on_regenerate_click()
        self.assertEqual(len(app.generated_pwd_value), 14)

        app._running = False


    def test_snackbar_reaches_the_page_through_a_supported_api(self) -> None:
        # Regression: the app used to assign page.snack_bar, which Flet no longer
        # renders, so every error message was silently invisible.
        self.assertTrue(hasattr(ft.Page, "show_dialog"))

        mock_page = MagicMock()
        app = LuxCipherFletApp(page=mock_page, account_store=MagicMock())
        mock_page.show_dialog.reset_mock()

        app._show_snackbar("messaggio di prova", is_error=True)

        mock_page.show_dialog.assert_called_once()
        self.assertIsInstance(mock_page.show_dialog.call_args.args[0], ft.SnackBar)
        app._running = False

    def test_setup_rejects_invalid_username_and_weak_master_password(self) -> None:
        with TemporaryDirectory() as directory:
            store = AccountStore(Path(directory) / "vault.db")
            app = LuxCipherFletApp(page=MagicMock(), account_store=store)

            # Username shorter than the 3 character minimum.
            app.auth_username_field.value = "ab"
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Master password shorter than MIN_MASTER_PASSWORD_LENGTH.
            app.auth_username_field.value = "test_user"
            app.auth_password_field.value = "short"
            app.auth_confirm_field.value = "short"
            app._submit_auth()
            self.assertFalse(store.is_open())

            # Both valid: the vault opens.
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertTrue(store.is_open())

            app._running = False
            store.close()

    def test_auto_lock_is_dispatched_to_the_ui_executor(self) -> None:
        # The inactivity timer runs on a background thread and must not touch
        # page controls directly.
        mock_page = MagicMock()
        app = LuxCipherFletApp(page=mock_page, account_store=MagicMock())
        callback = MagicMock()

        app._dispatch_to_ui(callback)

        mock_page.run_thread.assert_called_once_with(callback)
        callback.assert_not_called()
        app._running = False


if __name__ == "__main__":
    unittest.main()





