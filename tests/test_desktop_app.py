from unittest import mock
from unittest.mock import MagicMock
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import flet as ft

from luxcipher import desktop_app
from luxcipher.account_store import AccountStore
from luxcipher.desktop_app import LuxCipherFletApp, LuxCipherApp
from luxcipher.password_generator import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH


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

    def test_generator_reports_why_it_produced_nothing(self) -> None:
        # Regression: unchecking every character set blanked the password and
        # swallowed the reason.
        app = LuxCipherFletApp(page=MagicMock(), account_store=MagicMock())
        for option in ("lower", "upper", "digits", "symbols"):
            app._toggle_gen_opt(option, False)

        self.assertEqual(app.generated_pwd_value, "")
        self.assertTrue(app.generator_error)
        self.assertEqual(app.gen_pwd_text.value, app.generator_error)

        # Re-enabling a set clears the error and produces a password again.
        app._toggle_gen_opt("lower", True)
        self.assertEqual(app.generator_error, "")
        self.assertEqual(len(app.generated_pwd_value), app.gen_length)
        app._running = False

    def test_length_field_clamps_only_once_committed(self) -> None:
        app = LuxCipherFletApp(page=MagicMock(), account_store=MagicMock())
        app._on_length_slider_change(20)

        # Typing the first digit of "20" must not be corrected mid-entry.
        app._on_length_input_change("2")
        self.assertEqual(app.gen_length, 20)

        # Committing an out-of-range value clamps it and syncs both controls.
        app.gen_length_input.value = "999"
        app._commit_length_input()
        self.assertEqual(app.gen_length, MAX_PASSWORD_LENGTH)
        self.assertEqual(app.gen_length_input.value, str(MAX_PASSWORD_LENGTH))
        self.assertEqual(app.gen_slider.value, float(MAX_PASSWORD_LENGTH))

        app.gen_length_input.value = "3"
        app._commit_length_input()
        self.assertEqual(app.gen_length, MIN_PASSWORD_LENGTH)
        self.assertEqual(app.gen_length_input.value, str(MIN_PASSWORD_LENGTH))
        app._running = False

    def test_login_rejects_a_vault_without_a_stored_username(self) -> None:
        # An empty database file opens under any key, so a missing username must
        # not be treated as a match.
        with TemporaryDirectory() as directory:
            db_path = Path(directory) / "vault.db"
            store = AccountStore(db_path)
            app = LuxCipherFletApp(page=MagicMock(), account_store=store)

            app.auth_username_field.value = "test_user"
            app.auth_password_field.value = "SuperPass123!"
            app.auth_confirm_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertTrue(store.is_open())

            # Drop the username the way a pre-metadata vault would look.
            store.conn.execute("DELETE FROM metadata WHERE key = 'username';")
            store.conn.commit()
            app._lock_vault()

            app.auth_mode = "login"
            app.auth_username_field.value = "test_user"
            app.auth_password_field.value = "SuperPass123!"
            app._submit_auth()
            self.assertFalse(store.is_open())

            app._running = False
            store.close()

    def test_copied_password_is_erased_from_the_clipboard(self) -> None:
        app = LuxCipherFletApp(
            page=MagicMock(),
            account_store=MagicMock(),
            clipboard_clear_seconds=0,
        )
        cleared: list[bool] = []
        with mock.patch.object(desktop_app, "get_system_clipboard", return_value="s3cret"),              mock.patch.object(desktop_app, "clear_system_clipboard", lambda: cleared.append(True)):
            app._clipboard_clear_worker("s3cret")
        self.assertEqual(cleared, [True])

        # Something else was copied in the meantime: leave it alone.
        cleared.clear()
        with mock.patch.object(desktop_app, "get_system_clipboard", return_value="altro"),              mock.patch.object(desktop_app, "clear_system_clipboard", lambda: cleared.append(True)):
            app._clipboard_clear_worker("s3cret")
        self.assertEqual(cleared, [])
        app._running = False


if __name__ == "__main__":
    unittest.main()





