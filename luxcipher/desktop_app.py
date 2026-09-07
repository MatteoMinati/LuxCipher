"""Modern Minimal Pop desktop interface for LuxCipher password manager with Flet."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any

import flet as ft

from luxcipher.account_store import AccountStore, AccountStoreError
from luxcipher.autotype import (
    DEFAULT_HOTKEY_LABEL,
    HotkeyListener,
    foreground_window,
    match_credential,
    type_credential,
)
from luxcipher.auth import (
    MIN_MASTER_PASSWORD_LENGTH,
    derive_master_key,
    get_or_create_salt,
    is_master_password_strong_enough,
    normalize_username,
)
from luxcipher.password_generator import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordOptions,
    evaluate_password_strength,
    generate_password,
)

AUTO_LOCK_TIMEOUT_SECONDS = 20 * 60  # 20 minutes (1200 seconds)
CLIPBOARD_CLEAR_SECONDS = 30
WINDOW_TITLE = "LuxCipher — Secure Password Vault"
AUTOTYPE_SETTING_KEY = "autotype_enabled"

# Colors - Clean Minimal Dark Palette
BG_ROOT = "#0C0D15"
BG_CARD = "#131524"
BG_INPUT = "#181A2D"
BORDER_COLOR = "#22253E"
BORDER_FOCUS = "#7C3AED"

PURPLE_PRIMARY = "#7C3AED"       # Vibrant Electric Violet
PURPLE_HOVER = "#8B5CF6"
CYAN_ACCENT = "#38BDF8"          # Modern Sky / Cyan
EMERALD_ACCENT = "#34D399"       # Mint / Emerald
ROSE_DANGER = "#F43F5E"          # Rose Red
TEXT_WHITE = "#F8FAFC"
TEXT_MUTED = "#94A3B8"
TEXT_SUBTLE = "#64748B"
BTN_DARK = "#1E2138"


def default_backup_dir() -> Path:
    """Backups go under the Documents folder, where the user can find them."""
    profile = os.environ.get("USERPROFILE")
    base = Path(profile) if profile else Path.home()
    return base / "Documents" / "LuxCipher Backups"


def make_padding(horizontal: int = 0, vertical: int = 0) -> ft.Padding:
    return ft.Padding(left=horizontal, top=vertical, right=horizontal, bottom=vertical)


def make_border(color: str = BORDER_COLOR, width: int = 1) -> ft.Border:
    side = ft.BorderSide(width, color)
    return ft.Border(top=side, right=side, bottom=side, left=side)


CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


def set_system_clipboard(text: str) -> None:
    """Fast, native Windows clipboard copy without Tkinter interference."""
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [wt.HWND]
        user32.OpenClipboard.restype = wt.BOOL
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = wt.BOOL
        user32.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
        user32.SetClipboardData.restype = wt.HANDLE
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wt.BOOL

        kernel32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
        kernel32.GlobalAlloc.restype = wt.HGLOBAL
        kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalLock.restype = wt.LPVOID
        kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalUnlock.restype = wt.BOOL

        if not user32.OpenClipboard(None):
            return

        user32.EmptyClipboard()
        data = text.encode("utf-16le") + b"\x00\x00"
        h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
        if h_mem:
            ptr = kernel32.GlobalLock(h_mem)
            if ptr:
                ctypes.memmove(ptr, data, len(data))
                kernel32.GlobalUnlock(h_mem)
                user32.SetClipboardData(CF_UNICODETEXT, h_mem)
        user32.CloseClipboard()
    except Exception:
        pass


def get_system_clipboard() -> str | None:
    """Return the clipboard's Unicode text, or None when it holds anything else."""
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.OpenClipboard.argtypes = [wt.HWND]
        user32.OpenClipboard.restype = wt.BOOL
        user32.GetClipboardData.argtypes = [wt.UINT]
        user32.GetClipboardData.restype = wt.HANDLE
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wt.BOOL
        kernel32.GlobalLock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalLock.restype = wt.LPVOID
        kernel32.GlobalUnlock.argtypes = [wt.HGLOBAL]
        kernel32.GlobalUnlock.restype = wt.BOOL

        if not user32.OpenClipboard(None):
            return None
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None

            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                return None
            try:
                return ctypes.wstring_at(pointer)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    except Exception:
        return None


def clear_system_clipboard() -> None:
    """Empty the clipboard so a copied password does not linger there."""
    try:
        user32 = ctypes.windll.user32
        user32.OpenClipboard.argtypes = [wt.HWND]
        user32.OpenClipboard.restype = wt.BOOL
        user32.EmptyClipboard.argtypes = []
        user32.EmptyClipboard.restype = wt.BOOL
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wt.BOOL

        if not user32.OpenClipboard(None):
            return
        user32.EmptyClipboard()
        user32.CloseClipboard()
    except Exception:
        pass


class LuxCipherFletApp:
    def __init__(
        self,
        page: ft.Page,
        account_store: AccountStore | None = None,
        auto_lock_timeout: float = AUTO_LOCK_TIMEOUT_SECONDS,
        clipboard_clear_seconds: float = CLIPBOARD_CLEAR_SECONDS,
    ) -> None:
        self.page = page
        self.account_store = account_store or AccountStore.default()
        self.auto_lock_timeout = auto_lock_timeout
        self.clipboard_clear_seconds = clipboard_clear_seconds
        self.last_activity_time = time.time()
        self._running = True
        self.current_username = ""
        self.auth_mode = "setup" if not self.account_store.exists() else "login"
        self.active_tab = "vault"  # "vault" or "generator"
        self.show_passwords_in_table = False
        self.revealed_ids: set[int] = set()
        # Kept so 'change master password' can check the current one without
        # a second trip through the database.
        self._current_key: bytes | None = None
        self.autotype_enabled = False
        self._hotkey = HotkeyListener(callback=self._on_autotype_hotkey)

        # Generator state
        self.gen_length = 20
        self.gen_lowercase = True
        self.gen_uppercase = True
        self.gen_digits = True
        self.gen_symbols = True
        self.gen_no_ambiguous = False
        self.generated_pwd_value = ""
        self.generator_error = ""

        # Generator controls
        self.gen_pwd_text = ft.Text(
            "",
            font_family="Consolas",
            size=14,
            weight=ft.FontWeight.W_700,
            color=CYAN_ACCENT,
            selectable=True,
        )
        self.gen_slider = ft.Slider(
            min=MIN_PASSWORD_LENGTH,
            max=MAX_PASSWORD_LENGTH,
            divisions=MAX_PASSWORD_LENGTH - MIN_PASSWORD_LENGTH,
            value=float(self.gen_length),
            label="{value}",
            active_color=PURPLE_PRIMARY,
        )
        self.gen_length_input = ft.TextField(
            value=str(self.gen_length),
            width=58,
            height=32,
            text_size=12,
            text_align=ft.TextAlign.CENTER,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=8,
            color=TEXT_WHITE,
            content_padding=make_padding(horizontal=4, vertical=4),
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        self.gen_strength_bar = ft.ProgressBar(
            value=0.85,
            color=EMERALD_ACCENT,
            bgcolor="#1A1C30",
            height=6,
            border_radius=3,
        )
        self.gen_strength_label = ft.Text(
            "Molto Forte",
            size=11,
            weight=ft.FontWeight.W_700,
            color=EMERALD_ACCENT,
        )

        # References for test/direct access
        self.auth_username_field = ft.TextField()
        self.auth_password_field = ft.TextField()
        self.auth_confirm_field = ft.TextField()
        self.new_service_field = ft.TextField()
        self.new_user_field = ft.TextField()
        self.new_pwd_field = ft.TextField()
        self.search_query = ""
        self.search_field = ft.TextField()

        self._configure_page()
        self._generate_pwd()
        self._start_inactivity_timer()
        self.render()

    @property
    def _salt_path(self) -> Path:
        return self.account_store.path.with_name("vault.salt")

    def _start_inactivity_timer(self) -> None:
        def _timer_loop() -> None:
            while self._running:
                time.sleep(2)
                if not self._running:
                    break
                if self.account_store.is_open():
                    elapsed = time.time() - self.last_activity_time
                    if elapsed >= self.auto_lock_timeout:
                        self._dispatch_to_ui(self._trigger_auto_lock)

        self._timer_thread = threading.Thread(
            target=_timer_loop,
            daemon=True,
            name="LuxCipherInactivityTimer",
        )
        self._timer_thread.start()

    def _on_keyboard(self, e: Any) -> None:
        """Every keypress counts as activity; a few also do something."""
        self.record_activity()
        if not self.account_store.is_open():
            return

        key = getattr(e, "key", "") or ""
        ctrl = bool(getattr(e, "ctrl", False))

        if key == "Escape":
            self._lock_vault()
        elif ctrl and key.lower() == "f":
            self._focus_search()
        elif ctrl and key.lower() == "n":
            self._set_active_tab("vault")

    def _focus_search(self) -> None:
        try:
            self.search_field.focus()
        except Exception:
            pass

    def _dispatch_to_ui(self, callback: Any) -> None:
        """Hand callback to Flet's executor: page controls are not thread-safe."""
        try:
            self.page.run_thread(callback)
        except Exception:
            callback()

    def record_activity(self) -> None:
        """Update timestamp on any user interaction to prevent timeout."""
        self.last_activity_time = time.time()

    def _trigger_auto_lock(self) -> None:
        """Lock vault and notify the user when timeout is reached."""
        if not self.account_store.is_open():
            return
        self._lock_vault()
        try:
            self._show_snackbar("Sessione scaduta per inattività (20 min). Vault bloccato.", is_error=True)
        except Exception:
            pass

    def _configure_page(self) -> None:
        self.page.title = WINDOW_TITLE
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = BG_ROOT
        self.page.padding = 0

        try:
            self.page.on_keyboard_event = self._on_keyboard
        except Exception:
            pass

        try:
            self.page.window.title_bar_hidden = True
            self.page.window.title_bar_buttons_hidden = True
            self.page.window.frameless = True
            self.page.window.width = 640
            self.page.window.height = 860
            self.page.window.min_width = 520
            self.page.window.min_height = 720
            self.page.window.prevent_close = False
            self.page.window.on_event = self._on_window_event
            if hasattr(self.page, "run_task") and hasattr(self.page.window, "center"):
                self.page.run_task(self.page.window.center)
            elif hasattr(self.page.window, "center"):
                self.page.window.center()
        except Exception:
            pass

    def _on_window_event(self, e: Any) -> None:
        if getattr(e, "data", "") in ("close", "destroy"):
            self._close_window()

    def _build_custom_title_bar(self) -> ft.Control:
        return ft.Container(
            bgcolor="#0E101B",
            padding=make_padding(horizontal=16, vertical=8),
            border=ft.Border(bottom=ft.BorderSide(1, "#1A1C2C")),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.WindowDragArea(
                        expand=True,
                        content=ft.Row(
                            spacing=8,
                            controls=[
                                ft.Icon(ft.Icons.LOCK_ROUNDED, color=PURPLE_HOVER, size=16),
                                ft.Text("LuxCipher", weight=ft.FontWeight.W_700, size=13, color=TEXT_WHITE),
                            ],
                        ),
                    ),
                    ft.Row(
                        spacing=0,
                        controls=[
                            ft.IconButton(
                                icon=ft.Icons.REMOVE_ROUNDED,
                                icon_color=TEXT_MUTED,
                                icon_size=16,
                                tooltip="Riduci a icona",
                                on_click=lambda _: self._minimize_window(),
                            ),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE_ROUNDED,
                                icon_color=TEXT_MUTED,
                                icon_size=16,
                                tooltip="Chiudi",
                                on_click=lambda _: self._close_window(),
                            ),
                        ],
                    ),
                ],
            ),
        )

    def _minimize_window(self) -> None:
        self.record_activity()
        try:
            self.page.window.minimized = True
            self.page.window.update()
        except Exception:
            try:
                self.page.update()
            except Exception:
                pass

    def _close_window(self) -> None:
        self._running = False
        try:
            self._hotkey.stop()
        except Exception:
            pass
        try:
            self.account_store.close()
        except Exception:
            pass
        try:
            if hasattr(self.page, "run_task") and hasattr(self.page.window, "close"):
                fut = self.page.run_task(self.page.window.close)
                if fut:
                    fut.result(timeout=0.5)
        except Exception:
            pass
        try:
            if hasattr(self.page, "run_task") and hasattr(self.page.window, "destroy"):
                fut = self.page.run_task(self.page.window.destroy)
                if fut:
                    fut.result(timeout=0.5)
        except Exception:
            pass
        try:
            hwnd = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
            if hwnd:
                WM_CLOSE = 0x0010
                ctypes.windll.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        except Exception:
            pass

        self._force_exit_after_grace()

    def _force_exit_after_grace(self, grace_seconds: float = 1.5) -> None:
        """Terminate the process only if the clean shutdown above did not.

        The Flet desktop host has been seen keeping the process alive after the
        window closes, which is why this fallback exists. Calling os._exit
        immediately skipped every flush and atexit handler even when the clean
        path would have worked, so it now runs on a daemon watchdog: if the
        process exits on its own first, this never fires.
        """
        def _watchdog() -> None:
            time.sleep(grace_seconds)
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            os._exit(0)

        threading.Thread(
            target=_watchdog,
            daemon=True,
            name="LuxCipherExitWatchdog",
        ).start()

    def _show_snackbar(self, message: str, is_error: bool = False) -> None:
        # Flet dropped page.snack_bar: assigning it creates a plain attribute that
        # is never rendered, which silently hid every error message from the user.
        try:
            self.page.show_dialog(
                ft.SnackBar(
                    content=ft.Text(message, color=TEXT_WHITE, weight=ft.FontWeight.W_500),
                    bgcolor=ROSE_DANGER if is_error else EMERALD_ACCENT,
                    duration=3000,
                )
            )
        except Exception:
            pass

    def render(self) -> None:
        self.page.controls.clear()
        self.page.add(self._build_custom_title_bar())

        if self.account_store.is_open():
            self.page.add(self._build_vault_view())
        else:
            self.page.add(self._build_auth_view())

        try:
            self.page.update()
        except Exception:
            pass

    # --- AUTH VIEW (CLEAN & CENTERED) ---
    def _build_auth_view(self) -> ft.Control:
        is_login = self.auth_mode == "login"

        btn_accedi = ft.Container(
            content=ft.Text("Accedi", color=TEXT_WHITE if is_login else TEXT_MUTED, weight=ft.FontWeight.W_700, size=12),
            bgcolor=PURPLE_PRIMARY if is_login else ft.Colors.TRANSPARENT,
            border_radius=18,
            padding=make_padding(horizontal=24, vertical=7),
            on_click=lambda _: self._set_auth_mode("login"),
            ink=True,
        )
        btn_registrati = ft.Container(
            content=ft.Text("Registrati", color=TEXT_WHITE if not is_login else TEXT_MUTED, weight=ft.FontWeight.W_700, size=12),
            bgcolor=PURPLE_PRIMARY if not is_login else ft.Colors.TRANSPARENT,
            border_radius=18,
            padding=make_padding(horizontal=24, vertical=7),
            on_click=lambda _: self._set_auth_mode("setup"),
            ink=True,
        )

        switcher_pill = ft.Container(
            bgcolor="#17192A",
            border_radius=20,
            border=make_border("#22253C"),
            padding=3,
            content=ft.Row([btn_accedi, btn_registrati], tight=True),
        )

        switcher_row = ft.Row([switcher_pill], alignment=ft.MainAxisAlignment.CENTER)

        # Form fields with identical geometry and border radius
        self.auth_username_field = ft.TextField(
            hint_text="Nome utente",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=13),
            text_align=ft.TextAlign.LEFT,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=12,
            color=TEXT_WHITE,
            text_size=13,
            content_padding=make_padding(horizontal=14, vertical=12),
            height=44,
            autofocus=True,
        )

        self.auth_password_field = ft.TextField(
            hint_text="Master password",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=13),
            text_align=ft.TextAlign.LEFT,
            password=True,
            can_reveal_password=True,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=12,
            color=TEXT_WHITE,
            text_size=13,
            content_padding=make_padding(horizontal=14, vertical=12),
            height=44,
            on_submit=lambda _: self._submit_auth(),
        )

        self.auth_confirm_field = ft.TextField(
            hint_text="Conferma master password",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=13),
            text_align=ft.TextAlign.LEFT,
            password=True,
            can_reveal_password=True,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=12,
            color=TEXT_WHITE,
            text_size=13,
            content_padding=make_padding(horizontal=14, vertical=12),
            height=44,
            on_submit=lambda _: self._submit_auth(),
        )

        action_btn = ft.Container(
            content=ft.Text("Accedi" if is_login else "Crea account", color=TEXT_WHITE, weight=ft.FontWeight.W_700, size=14),
            bgcolor=PURPLE_PRIMARY,
            border_radius=12,
            height=44,
            alignment=ft.Alignment(0, 0),
            on_click=lambda _: self._submit_auth(),
            ink=True,
        )

        form_items: list[ft.Control] = [
            ft.Text("NOME UTENTE", size=10, weight=ft.FontWeight.W_700, color=TEXT_MUTED),
            self.auth_username_field,
            ft.Container(height=4),
            ft.Text("MASTER PASSWORD", size=10, weight=ft.FontWeight.W_700, color=TEXT_MUTED),
            self.auth_password_field,
        ]

        if not is_login:
            form_items.extend([
                ft.Container(height=4),
                ft.Text("CONFERMA PASSWORD", size=10, weight=ft.FontWeight.W_700, color=TEXT_MUTED),
                self.auth_confirm_field,
            ])

        form_items.extend([
            ft.Container(height=10),
            action_btn,
        ])

        form_column = ft.Column(
            controls=form_items,
            spacing=4,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        )

        bottom_link = ft.Row(
            alignment=ft.MainAxisAlignment.CENTER,
            controls=[
                ft.Text("Non hai un account? " if is_login else "Hai già un account? ", color=TEXT_MUTED, size=12),
                ft.Text(
                    "Crea un account" if is_login else "Accedi",
                    color=PURPLE_HOVER,
                    weight=ft.FontWeight.W_700,
                    size=12,
                ),
            ],
        )

        bottom_link_container = ft.GestureDetector(
            content=bottom_link,
            on_tap=lambda _: self._set_auth_mode("setup" if is_login else "login"),
        )

        return ft.Container(
            alignment=ft.Alignment(0, 0),
            expand=True,
            padding=make_padding(horizontal=24, vertical=16),
            content=ft.Container(
                width=380,
                content=ft.Column(
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=8,
                    controls=[
                        switcher_row,
                        ft.Container(height=6),
                        ft.Text(
                            "Bentornato." if is_login else "Crea account.",
                            size=26,
                            weight=ft.FontWeight.W_700,
                            color=TEXT_WHITE,
                            text_align=ft.TextAlign.CENTER,
                        ),
                        ft.Text(
                            "Accedi per gestire le tue credenziali cifrate." if is_login else "Inizia a proteggere le tue password in locale.",
                            size=12,
                            color=TEXT_MUTED,
                            text_align=ft.TextAlign.CENTER,
                        ),
                        ft.Container(height=10),
                        form_column,
                        ft.Container(height=8),
                        bottom_link_container,
                    ],
                ),
            ),
        )

    def _set_auth_mode(self, mode: str) -> None:
        self.record_activity()
        self.auth_mode = mode
        self.render()

    def _submit_auth(self) -> None:
        self.record_activity()
        username = self.auth_username_field.value.strip() if self.auth_username_field.value else ""
        password = self.auth_password_field.value if self.auth_password_field.value else ""

        if not username:
            self._show_snackbar("Inserisci il nome utente", is_error=True)
            return

        if not password:
            self._show_snackbar("Inserisci la master password", is_error=True)
            return

        if self.auth_mode == "setup":
            confirm = self.auth_confirm_field.value if self.auth_confirm_field.value else ""
            if password != confirm:
                self._show_snackbar("Le master password non coincidono", is_error=True)
                return

            try:
                username = normalize_username(username)
            except ValueError:
                self._show_snackbar(
                    "Il nome utente deve avere 3-64 caratteri e contenere solo "
                    "lettere, numeri, '.', '_' o '-'",
                    is_error=True,
                )
                return

            if not is_master_password_strong_enough(password):
                self._show_snackbar(
                    f"La master password deve avere almeno {MIN_MASTER_PASSWORD_LENGTH} caratteri",
                    is_error=True,
                )
                return

            try:
                master_key = derive_master_key(password, salt_path=self._salt_path)
                self.account_store.open(master_key)
                self.account_store.set_account_username(username)
                self._current_key = master_key
            except Exception as error:
                self._show_snackbar(str(error), is_error=True)
                return

            self.current_username = username
            self._load_autotype_setting()
            self._show_snackbar("Account creato e Vault inizializzato!")
            self.render()

        else:  # login
            try:
                master_key = derive_master_key(password, salt_path=self._salt_path)
                self.account_store.open(master_key)
                self._current_key = master_key

                # A missing username means this is not a vault set up by the app:
                # an empty database file accepts any key, so treating None as a
                # pass would let any password through.
                saved_user = self.account_store.get_account_username()
                if saved_user is None or saved_user.strip().lower() != username.lower():
                    self.account_store.close()
                    self._show_snackbar("Nome Utente o Master Password errati", is_error=True)
                    return

            except ValueError as error:
                self._show_snackbar(str(error), is_error=True)
                return
            except Exception as error:
                self._show_snackbar(f"Errore di accesso: {error}", is_error=True)
                return

            self.current_username = username
            self._load_autotype_setting()
            self.render()

    # --- VAULT UNLOCKED VIEW (CLEAN, MINIMAL & CENTERED) ---
    def _build_vault_view(self) -> ft.Control:
        user_header = ft.Container(
            padding=make_padding(vertical=4),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        spacing=10,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            ft.Container(
                                content=ft.Icon(ft.Icons.PERSON_ROUNDED, color=TEXT_WHITE, size=18),
                                bgcolor="#22253A",
                                border_radius=18,
                                width=36,
                                height=36,
                                alignment=ft.Alignment(0, 0),
                            ),
                            ft.Column(
                                spacing=1,
                                alignment=ft.MainAxisAlignment.CENTER,
                                controls=[
                                    ft.Text(self.current_username or "Utente", weight=ft.FontWeight.W_700, size=14, color=TEXT_WHITE),
                                    ft.Row(
                                        spacing=4,
                                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                                        controls=[
                                            ft.Container(width=6, height=6, border_radius=3, bgcolor=EMERALD_ACCENT),
                                            ft.Text("Vault Cifrato", size=10, weight=ft.FontWeight.W_600, color=CYAN_ACCENT),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=2,
                        tight=True,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            ft.IconButton(
                                icon=ft.Icons.BACKUP_OUTLINED,
                                icon_color=TEXT_MUTED,
                                icon_size=16,
                                tooltip="Crea un backup del vault",
                                on_click=lambda _: self._create_backup(),
                            ),
                            ft.IconButton(
                                icon=ft.Icons.KEY_OUTLINED,
                                icon_color=TEXT_MUTED,
                                icon_size=16,
                                tooltip="Cambia master password",
                                on_click=lambda _: self._open_change_master_password(),
                            ),
                            self._build_logout_pill(),
                        ],
                    ),
                ],
            ),
        )

        # Centered Tab Segmented Switcher
        is_vault_tab = self.active_tab == "vault"
        tab_btn_vault = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.STORAGE_ROUNDED, size=13, color=TEXT_WHITE if is_vault_tab else TEXT_MUTED),
                    ft.Text("Credenziali", color=TEXT_WHITE if is_vault_tab else TEXT_MUTED, weight=ft.FontWeight.W_600, size=12),
                ],
                spacing=6,
                tight=True,
            ),
            bgcolor=PURPLE_PRIMARY if is_vault_tab else ft.Colors.TRANSPARENT,
            border_radius=16,
            padding=make_padding(horizontal=16, vertical=7),
            on_click=lambda _: self._set_active_tab("vault"),
            ink=True,
        )
        tab_btn_gen = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.KEY_ROUNDED, size=13, color=TEXT_WHITE if not is_vault_tab else TEXT_MUTED),
                    ft.Text("Generatore", color=TEXT_WHITE if not is_vault_tab else TEXT_MUTED, weight=ft.FontWeight.W_600, size=12),
                ],
                spacing=6,
                tight=True,
            ),
            bgcolor=PURPLE_PRIMARY if not is_vault_tab else ft.Colors.TRANSPARENT,
            border_radius=16,
            padding=make_padding(horizontal=16, vertical=7),
            on_click=lambda _: self._set_active_tab("generator"),
            ink=True,
        )

        tab_switcher = ft.Container(
            bgcolor="#17192A",
            border_radius=18,
            border=make_border("#22253C"),
            padding=3,
            content=ft.Row([tab_btn_vault, tab_btn_gen], tight=True),
        )
        tab_switcher_row = ft.Row([tab_switcher], alignment=ft.MainAxisAlignment.CENTER)

        content_body = self._build_credentials_tab() if is_vault_tab else self._build_generator_tab()

        return ft.Container(
            alignment=ft.Alignment(0, 0),
            padding=make_padding(horizontal=20, vertical=8),
            expand=True,
            content=ft.Container(
                width=440,
                content=ft.Column(
                    expand=True,
                    spacing=8,
                    scroll=ft.ScrollMode.AUTO,
                    controls=[
                        user_header,
                        tab_switcher_row,
                        ft.Divider(height=1, color="#1E2033"),
                        content_body,
                    ],
                ),
            ),
        )

    def _build_logout_pill(self) -> ft.Control:
        return ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.LOGOUT_ROUNDED, color="#FDA4AF", size=13),
                    ft.Text("Esci", color="#FDA4AF", size=11, weight=ft.FontWeight.W_600),
                ],
                spacing=4,
                tight=True,
            ),
            bgcolor="#2A1520",
            border=make_border("#4C1D2A"),
            border_radius=14,
            padding=make_padding(horizontal=10, vertical=5),
            tooltip="Blocca il vault (Esc)",
            on_click=lambda _: self._lock_vault(),
            ink=True,
        )

    def _set_active_tab(self, tab_name: str) -> None:
        self.record_activity()
        self.active_tab = tab_name
        self.render()

    def _get_account_cards(self) -> list[ft.Control]:
        accounts = []
        if self.account_store.is_open():
            if self.search_query.strip():
                accounts = self.account_store.search_accounts(self.search_query.strip())
            else:
                accounts = self.account_store.get_all_accounts()

        if not accounts:
            empty_text = (
                f"Nessuna credenziale trovata per '{self.search_query}'"
                if self.search_query.strip()
                else "Nessuna credenziale salvata"
            )
            empty_subtext = (
                "Prova con un altro termine di ricerca"
                if self.search_query.strip()
                else "Aggiungi la prima credenziale dal form qui sopra"
            )
            return [
                ft.Container(
                    alignment=ft.Alignment(0, 0),
                    padding=make_padding(vertical=20),
                    content=ft.Column(
                        alignment=ft.MainAxisAlignment.CENTER,
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        spacing=6,
                        controls=[
                            ft.Icon(
                                ft.Icons.SEARCH_OFF_ROUNDED if self.search_query.strip() else ft.Icons.SHIELD_OUTLINED,
                                size=26,
                                color=TEXT_SUBTLE,
                            ),
                            ft.Text(empty_text, color=TEXT_MUTED, size=12),
                            ft.Text(empty_subtext, color=TEXT_SUBTLE, size=10),
                        ],
                    ),
                )
            ]

        account_cards: list[ft.Control] = []
        for acc in accounts:
            acc_id, srv, uname, pwd = acc[0], acc[1], acc[2], acc[3]
            updated_at = acc[5] if len(acc) > 5 else ""
            revealed = self.show_passwords_in_table or acc_id in self.revealed_ids
            display_pwd = pwd if revealed else ("•" * min(len(pwd), 12))

            subtitle = uname or "(nessun username)"
            if updated_at:
                subtitle = f"{subtitle}  ·  agg. {updated_at[:10]}"

            card = ft.Container(
                bgcolor=BG_CARD,
                border_radius=12,
                border=make_border(BORDER_COLOR),
                padding=make_padding(horizontal=14, vertical=10),
                content=ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Column(
                            spacing=2,
                            expand=True,
                            controls=[
                                ft.Text(srv, weight=ft.FontWeight.W_700, size=13, color=TEXT_WHITE),
                                ft.Text(subtitle, size=11, color=TEXT_MUTED),
                                ft.Text(
                                    display_pwd,
                                    size=12,
                                    color=CYAN_ACCENT,
                                    font_family="Consolas",
                                    selectable=revealed,
                                ),
                            ],
                        ),
                        ft.Row(
                            spacing=0,
                            tight=True,
                            controls=[
                                self._card_action(
                                    ft.Icons.VISIBILITY_OFF_ROUNDED if revealed else ft.Icons.VISIBILITY_ROUNDED,
                                    TEXT_MUTED,
                                    "Nascondi" if revealed else "Mostra",
                                    lambda _, i=acc_id: self._toggle_revealed(i),
                                ),
                                self._card_action(
                                    ft.Icons.PERSON_OUTLINE_ROUNDED,
                                    CYAN_ACCENT,
                                    "Copia username",
                                    lambda _, u=uname: self._copy_to_clipboard(u, "Username copiato!"),
                                ),
                                self._card_action(
                                    ft.Icons.CONTENT_COPY_ROUNDED,
                                    EMERALD_ACCENT,
                                    "Copia password",
                                    lambda _, x=pwd: self._copy_to_clipboard(x),
                                ),
                                self._card_action(
                                    ft.Icons.EDIT_ROUNDED,
                                    PURPLE_HOVER,
                                    "Modifica",
                                    lambda _, i=acc_id: self._open_edit_dialog(i),
                                ),
                                self._card_action(
                                    ft.Icons.DELETE_OUTLINE_ROUNDED,
                                    ROSE_DANGER,
                                    "Elimina",
                                    lambda _, i=acc_id, n=srv: self._confirm_delete(i, n),
                                ),
                            ],
                        ),
                    ],
                ),
            )
            account_cards.append(card)
        return account_cards

    # --- auto-type ---

    def _load_autotype_setting(self) -> None:
        """Read the stored preference and start the hotkey if it is enabled."""
        try:
            enabled = self.account_store.get_setting(AUTOTYPE_SETTING_KEY, "0") == "1"
        except Exception:
            enabled = False

        self.autotype_enabled = enabled
        if enabled:
            self._hotkey.start()

    def _set_autotype_enabled(self, enabled: bool) -> None:
        self.record_activity()
        self.autotype_enabled = bool(enabled)
        try:
            self.account_store.set_setting(AUTOTYPE_SETTING_KEY, "1" if enabled else "0")
        except Exception as error:
            self._show_snackbar(f"Impossibile salvare l'impostazione: {error}", is_error=True)
            return

        if not enabled:
            self._hotkey.stop()
            self._show_snackbar("Auto-type disattivato")
            return

        if self._hotkey.start():
            self._show_snackbar(f"Auto-type attivo: premi {DEFAULT_HOTKEY_LABEL} su un login")
        else:
            self.autotype_enabled = False
            self._show_snackbar(
                f"{DEFAULT_HOTKEY_LABEL} e gia usato da un altro programma", is_error=True
            )

    def _on_autotype_hotkey(self) -> None:
        """Type the credential matching the focused window. Runs on the hotkey thread.

        Every early return here is a refusal to type. Typing a password into a
        window that was not confidently identified is the one failure this
        feature must never have, so anything ambiguous does nothing at all.
        """
        if not self.autotype_enabled or not self.account_store.is_open():
            return

        hwnd, title = foreground_window()
        if not hwnd or not title:
            return

        # Never type into our own window: the vault is not a login form, and the
        # search box would happily accept a password in plain sight.
        if title.strip() == WINDOW_TITLE:
            return

        try:
            match = match_credential(title, self.account_store.get_all_accounts())
        except Exception:
            return

        if match is None:
            return

        self.record_activity()
        type_credential(str(match[2] or ""), str(match[3] or ""), hwnd)

    def _build_autotype_row(self) -> ft.Control:
        return ft.Container(
            bgcolor=BG_CARD,
            border_radius=10,
            border=make_border(BORDER_COLOR),
            padding=make_padding(horizontal=12, vertical=6),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Column(
                        spacing=1,
                        expand=True,
                        controls=[
                            ft.Text(
                                "Auto-type",
                                size=12,
                                weight=ft.FontWeight.W_600,
                                color=TEXT_WHITE,
                            ),
                            ft.Text(
                                f"{DEFAULT_HOTKEY_LABEL} digita le credenziali nella "
                                "finestra attiva, riconoscendola dal titolo",
                                size=10,
                                color=TEXT_SUBTLE,
                            ),
                        ],
                    ),
                    ft.Switch(
                        value=self.autotype_enabled,
                        active_color=PURPLE_PRIMARY,
                        on_change=lambda e: self._set_autotype_enabled(e.control.value),
                    ),
                ],
            ),
        )

    def _card_action(self, icon: str, color: str, tooltip: str, on_click: Any) -> ft.Control:
        return ft.IconButton(
            icon=icon, icon_color=color, icon_size=15, tooltip=tooltip, on_click=on_click
        )

    def _toggle_revealed(self, account_id: int) -> None:
        self.record_activity()
        if account_id in self.revealed_ids:
            self.revealed_ids.discard(account_id)
        else:
            self.revealed_ids.add(account_id)
        self._refresh_cards()

    def _refresh_cards(self) -> None:
        """Rebuild only the list, so typing and scrolling are not interrupted."""
        try:
            self.cards_list.controls = self._get_account_cards()
            self.cards_list.update()
        except Exception:
            self.render()

    # --- dialogs ---

    def _close_dialog(self) -> None:
        try:
            self.page.pop_dialog()
        except Exception:
            pass

    def _show_dialog(self, dialog: ft.AlertDialog) -> None:
        try:
            self.page.show_dialog(dialog)
        except Exception:
            self._show_snackbar("Impossibile aprire la finestra", is_error=True)

    def _dialog_field(self, label: str, value: str, password: bool = False) -> ft.TextField:
        return ft.TextField(
            label=label,
            value=value,
            password=password,
            can_reveal_password=password,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=10,
            color=TEXT_WHITE,
            text_size=13,
            content_padding=make_padding(horizontal=12, vertical=10),
        )

    def _open_edit_dialog(self, account_id: int) -> None:
        self.record_activity()
        row = self.account_store.get_account(account_id)
        if row is None:
            self._show_snackbar("Credenziale non trovata", is_error=True)
            self._refresh_cards()
            return

        service_field = self._dialog_field("Servizio", row[1])
        user_field = self._dialog_field("Username o email", row[2])
        pwd_field = self._dialog_field("Password", row[3], password=True)

        def save(_: Any) -> None:
            self.record_activity()
            try:
                self.account_store.update_account(
                    account_id,
                    (service_field.value or "").strip(),
                    (user_field.value or "").strip(),
                    pwd_field.value or "",
                )
            except (ValueError, AccountStoreError) as error:
                self._show_snackbar(f"Modifica non riuscita: {error}", is_error=True)
                return
            self._close_dialog()
            self._show_snackbar("Credenziale aggiornata!")
            self._refresh_cards()

        def regenerate(_: Any) -> None:
            self.record_activity()
            self._generate_pwd()
            if self.generated_pwd_value:
                pwd_field.value = self.generated_pwd_value
                try:
                    pwd_field.update()
                except Exception:
                    pass

        self._show_dialog(
            ft.AlertDialog(
                modal=True,
                bgcolor=BG_CARD,
                title=ft.Text("Modifica credenziale", color=TEXT_WHITE, size=16),
                content=ft.Column(
                    tight=True,
                    spacing=10,
                    width=360,
                    controls=[
                        service_field,
                        user_field,
                        pwd_field,
                        ft.TextButton(
                            "Genera una nuova password",
                            icon=ft.Icons.AUTO_FIX_HIGH_ROUNDED,
                            on_click=regenerate,
                        ),
                    ],
                ),
                actions=[
                    ft.TextButton("Annulla", on_click=lambda _: self._close_dialog()),
                    ft.FilledButton("Salva", on_click=save),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
        )

    def _confirm_delete(self, account_id: int, service: str) -> None:
        self.record_activity()

        def do_delete(_: Any) -> None:
            try:
                self.account_store.delete_account(account_id)
            except AccountStoreError as error:
                self._show_snackbar(str(error), is_error=True)
                return
            self.revealed_ids.discard(account_id)
            self._close_dialog()
            self._show_snackbar(f"{service} eliminata")
            self.render()

        self._show_dialog(
            ft.AlertDialog(
                modal=True,
                bgcolor=BG_CARD,
                title=ft.Text("Eliminare la credenziale?", color=TEXT_WHITE, size=16),
                content=ft.Text(
                    f"{service} verra eliminata definitivamente. "
                    "Non e possibile recuperarla.",
                    color=TEXT_MUTED,
                    size=13,
                ),
                actions=[
                    ft.TextButton("Annulla", on_click=lambda _: self._close_dialog()),
                    ft.FilledButton(
                        "Elimina",
                        style=ft.ButtonStyle(bgcolor=ROSE_DANGER, color=TEXT_WHITE),
                        on_click=do_delete,
                    ),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
        )

    def _open_change_master_password(self) -> None:
        self.record_activity()
        current = self._dialog_field("Master password attuale", "", password=True)
        new = self._dialog_field("Nuova master password", "", password=True)
        confirm = self._dialog_field("Conferma nuova master password", "", password=True)

        def apply(_: Any) -> None:
            self.record_activity()
            salt = get_or_create_salt(self._salt_path)

            if derive_master_key(current.value or "", salt=salt) != self._current_key:
                self._show_snackbar("La master password attuale non e corretta", is_error=True)
                return
            if (new.value or "") != (confirm.value or ""):
                self._show_snackbar("Le nuove master password non coincidono", is_error=True)
                return
            if not is_master_password_strong_enough(new.value or ""):
                self._show_snackbar(
                    f"La nuova master password deve avere almeno "
                    f"{MIN_MASTER_PASSWORD_LENGTH} caratteri",
                    is_error=True,
                )
                return

            new_key = derive_master_key(new.value or "", salt=salt)
            try:
                self.account_store.change_master_key(new_key)
            except Exception as error:
                self._show_snackbar(f"Cambio non riuscito: {error}", is_error=True)
                return

            self._current_key = new_key
            self._close_dialog()
            self._show_snackbar("Master password aggiornata!")

        self._show_dialog(
            ft.AlertDialog(
                modal=True,
                bgcolor=BG_CARD,
                title=ft.Text("Cambia master password", color=TEXT_WHITE, size=16),
                content=ft.Column(
                    tight=True,
                    spacing=10,
                    width=360,
                    controls=[
                        ft.Text(
                            "Il vault viene ricifrato con la nuova password. "
                            "Il file vault.salt resta necessario.",
                            color=TEXT_MUTED,
                            size=12,
                        ),
                        current,
                        new,
                        confirm,
                    ],
                ),
                actions=[
                    ft.TextButton("Annulla", on_click=lambda _: self._close_dialog()),
                    ft.FilledButton("Cambia", on_click=apply),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
        )

    def _create_backup(self) -> None:
        self.record_activity()
        try:
            destination = self.account_store.backup_to(default_backup_dir())
        except Exception as error:
            self._show_snackbar(f"Backup non riuscito: {error}", is_error=True)
            return

        self._show_dialog(
            ft.AlertDialog(
                modal=True,
                bgcolor=BG_CARD,
                title=ft.Text("Backup creato", color=TEXT_WHITE, size=16),
                content=ft.Column(
                    tight=True,
                    spacing=8,
                    width=380,
                    controls=[
                        ft.Text(str(destination), color=CYAN_ACCENT, size=12, selectable=True),
                        ft.Text(
                            "La copia contiene vault.db e vault.salt. Servono entrambi: "
                            "il database da solo non e apribile.",
                            color=TEXT_MUTED,
                            size=12,
                        ),
                        ft.Text(
                            "Il backup e cifrato con la master password che stai usando "
                            "adesso. Se in futuro la cambi, questa copia continuera a "
                            "richiedere quella vecchia.",
                            color=TEXT_MUTED,
                            size=12,
                        ),
                    ],
                ),
                actions=[ft.FilledButton("Ho capito", on_click=lambda _: self._close_dialog())],
                actions_alignment=ft.MainAxisAlignment.END,
            )
        )

    def _build_credentials_tab(self) -> ft.Control:
        accounts = []
        if self.account_store.is_open():
            if self.search_query.strip():
                accounts = self.account_store.search_accounts(self.search_query.strip())
            else:
                accounts = self.account_store.get_all_accounts()

        # Clean form fields
        self.new_service_field = ft.TextField(
            hint_text="Servizio (es. Google, GitHub)",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=12),
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=10,
            text_size=13,
            color=TEXT_WHITE,
            content_padding=make_padding(horizontal=12, vertical=10),
            height=40,
        )
        self.new_user_field = ft.TextField(
            hint_text="Username o Email",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=12),
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=10,
            text_size=13,
            color=TEXT_WHITE,
            content_padding=make_padding(horizontal=12, vertical=10),
            height=40,
        )
        self.new_pwd_field = ft.TextField(
            hint_text="Password",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=12),
            password=True,
            can_reveal_password=True,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=10,
            text_size=13,
            color=TEXT_WHITE,
            expand=True,
            content_padding=make_padding(horizontal=12, vertical=10),
            height=40,
        )

        btn_fill_pwd = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.AUTO_FIX_HIGH_ROUNDED, size=14, color=CYAN_ACCENT),
                    ft.Text("Genera", size=11, color=TEXT_WHITE, weight=ft.FontWeight.W_600),
                ],
                spacing=4,
                tight=True,
            ),
            bgcolor=BTN_DARK,
            border=make_border(BORDER_COLOR),
            border_radius=10,
            padding=make_padding(horizontal=10, vertical=0),
            height=40,
            alignment=ft.Alignment(0, 0),
            on_click=lambda _: self._fill_generated_password(),
            ink=True,
        )

        save_btn = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.LOCK_ROUNDED, size=15, color=TEXT_WHITE),
                    ft.Text("Salva Credenziale nel Vault", color=TEXT_WHITE, weight=ft.FontWeight.W_600, size=13),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=8,
            ),
            bgcolor=PURPLE_PRIMARY,
            border_radius=10,
            height=40,
            alignment=ft.Alignment(0, 0),
            on_click=lambda _: self._add_account_entry(),
            ink=True,
        )

        add_form = ft.Container(
            bgcolor=BG_CARD,
            border_radius=14,
            border=make_border(BORDER_COLOR),
            padding=14,
            content=ft.Column(
                spacing=8,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                controls=[
                    ft.Row(
                        [
                            ft.Icon(ft.Icons.ADD_CIRCLE_OUTLINE_ROUNDED, size=14, color=CYAN_ACCENT),
                            ft.Text("NUOVA CREDENZIALE", size=10, weight=ft.FontWeight.W_700, color=CYAN_ACCENT),
                        ],
                        spacing=6,
                    ),
                    self.new_service_field,
                    self.new_user_field,
                    ft.Row([self.new_pwd_field, btn_fill_pwd], spacing=6),
                    save_btn,
                ],
            ),
        )

        # Search Bar
        self.search_field = ft.TextField(
            hint_text="Cerca servizio, username o email...",
            hint_style=ft.TextStyle(color=TEXT_SUBTLE, size=12),
            prefix_icon=ft.Icons.SEARCH_ROUNDED,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=BORDER_FOCUS,
            border_radius=10,
            text_size=12,
            color=TEXT_WHITE,
            content_padding=make_padding(horizontal=12, vertical=8),
            height=38,
            value=self.search_query,
            on_change=lambda e: self._on_search_change(e.control.value),
        )

        self.cards_list = ft.ListView(
            controls=self._get_account_cards(),
            spacing=6,
            expand=True,
        )

        count_label_text = f"{len(accounts)} Trovate" if self.search_query.strip() else f"{len(accounts)} Credenziali Salvate"
        self.count_label_control = ft.Text(count_label_text, weight=ft.FontWeight.W_700, size=11, color=TEXT_MUTED)

        self.toggle_btn_icon = ft.Icon(
            ft.Icons.VISIBILITY_OFF if self.show_passwords_in_table else ft.Icons.VISIBILITY,
            size=13,
            color=TEXT_MUTED,
        )
        self.toggle_btn_text = ft.Text(
            "Nascondi" if self.show_passwords_in_table else "Mostra in chiaro",
            size=11,
            color=TEXT_MUTED,
        )
        self.toggle_btn = ft.Container(
            content=ft.Row(
                [self.toggle_btn_icon, self.toggle_btn_text],
                spacing=4,
                tight=True,
            ),
            on_click=lambda _: self._toggle_table_passwords(),
            ink=True,
        )

        return ft.Container(
            expand=True,
            content=ft.Column(
                expand=True,
                spacing=8,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                controls=[
                    add_form,
                    self._build_autotype_row(),
                    self.search_field,
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            self.count_label_control,
                            self.toggle_btn,
                        ],
                    ),
                    self.cards_list,
                ],
            ),
        )

    def _on_search_change(self, query: str) -> None:
        self.record_activity()
        self.search_query = query
        try:
            self.cards_list.controls = self._get_account_cards()
            accounts = (
                self.account_store.search_accounts(self.search_query.strip())
                if self.search_query.strip()
                else self.account_store.get_all_accounts()
            )
            self.count_label_control.value = (
                f"{len(accounts)} Trovate"
                if self.search_query.strip()
                else f"{len(accounts)} Credenziali Salvate"
            )
            self.cards_list.update()
            self.count_label_control.update()
        except Exception:
            self.render()

    def _toggle_table_passwords(self) -> None:
        self.record_activity()
        self.show_passwords_in_table = not self.show_passwords_in_table
        try:
            self.cards_list.controls = self._get_account_cards()
            self.toggle_btn_text.value = "Nascondi" if self.show_passwords_in_table else "Mostra in chiaro"
            self.toggle_btn_icon.name = (
                ft.Icons.VISIBILITY_OFF if self.show_passwords_in_table else ft.Icons.VISIBILITY
            )
            self.cards_list.update()
            self.toggle_btn.update()
        except Exception:
            self.render()

    def _copy_to_clipboard(self, text: str, label: str = "Password copiata!") -> None:
        self.record_activity()
        if not text:
            self._show_snackbar("Niente da copiare", is_error=True)
            return
        set_system_clipboard(text)
        try:
            self.page.clipboard.set(text)
        except Exception:
            pass

        self._schedule_clipboard_clear(text)
        self._show_snackbar(
            f"{label} Gli appunti si svuotano tra "
            f"{int(self.clipboard_clear_seconds)}s."
        )

    def _schedule_clipboard_clear(self, copied: str) -> None:
        """Erase the copied password from the clipboard after a delay."""
        thread = threading.Thread(
            target=self._clipboard_clear_worker,
            args=(copied,),
            daemon=True,
            name="LuxCipherClipboardCleaner",
        )
        thread.start()

    def _clipboard_clear_worker(self, copied: str) -> None:
        time.sleep(self.clipboard_clear_seconds)
        # Only erase our own password: the user may have copied something else
        # in the meantime, and wiping that would be destructive.
        if get_system_clipboard() == copied:
            clear_system_clipboard()

    def _fill_generated_password(self) -> None:
        self.record_activity()
        if not self.generated_pwd_value:
            self._generate_pwd()
        self.new_pwd_field.value = self.generated_pwd_value
        try:
            self.new_pwd_field.update()
        except Exception:
            pass
        self._show_snackbar("Password generata inserita nel form!")

    def _add_account_entry(self) -> None:
        self.record_activity()
        srv = self.new_service_field.value.strip() if self.new_service_field.value else ""
        uname = self.new_user_field.value.strip() if self.new_user_field.value else ""
        pwd = self.new_pwd_field.value if self.new_pwd_field.value else ""

        if not srv or not uname or not pwd:
            self._show_snackbar("Tutti i campi sono obbligatori", is_error=True)
            return

        try:
            self.account_store.add_account(srv, uname, pwd)
            self.new_service_field.value = ""
            self.new_user_field.value = ""
            self.new_pwd_field.value = ""
            self._show_snackbar("Credenziale salvata con successo!")
            self.render()
        except Exception as error:
            self._show_snackbar(f"Errore durante il salvataggio: {error}", is_error=True)

    def _build_generator_tab(self) -> ft.Control:
        if not self.generated_pwd_value:
            self._generate_pwd()

        score, label, color_hex = evaluate_password_strength(self.generated_pwd_value)
        self.gen_pwd_text.value = self.generated_pwd_value or self.generator_error
        self.gen_pwd_text.color = ROSE_DANGER if self.generator_error else CYAN_ACCENT
        self.gen_strength_label.value = label
        self.gen_strength_label.color = color_hex
        self.gen_strength_bar.value = score
        self.gen_strength_bar.color = color_hex
        self.gen_slider.value = float(self.gen_length)
        self.gen_length_input.value = str(self.gen_length)

        pwd_display = ft.Container(
            bgcolor=BG_INPUT,
            border_radius=12,
            border=make_border(BORDER_COLOR),
            padding=make_padding(horizontal=14, vertical=8),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    self.gen_pwd_text,
                    ft.Container(
                        content=ft.IconButton(
                            icon=ft.Icons.CONTENT_COPY_ROUNDED,
                            icon_color=EMERALD_ACCENT,
                            icon_size=16,
                            tooltip="Copia Password",
                            on_click=lambda _: self._copy_to_clipboard(self.generated_pwd_value),
                        ),
                        bgcolor="#192C26",
                        border_radius=10,
                    ),
                ],
            ),
        )

        strength_card = ft.Container(
            bgcolor=BG_CARD,
            border_radius=12,
            border=make_border(BORDER_COLOR),
            padding=make_padding(horizontal=14, vertical=8),
            content=ft.Column(
                spacing=4,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Sicurezza Password", size=11, weight=ft.FontWeight.W_600, color=TEXT_MUTED),
                            self.gen_strength_label,
                        ],
                    ),
                    self.gen_strength_bar,
                ],
            ),
        )

        self.gen_slider.on_change = lambda e: self._on_length_slider_change(int(e.control.value))
        self.gen_length_input.on_change = lambda e: self._on_length_input_change(e.control.value)
        self.gen_length_input.on_blur = lambda _: self._commit_length_input()
        self.gen_length_input.on_submit = lambda _: self._commit_length_input()

        options_card = ft.Container(
            bgcolor=BG_CARD,
            border_radius=14,
            border=make_border(BORDER_COLOR),
            padding=12,
            content=ft.Column(
                spacing=2,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            ft.Text("Lunghezza caratteri", weight=ft.FontWeight.W_600, size=12, color=TEXT_WHITE),
                            self.gen_length_input,
                        ],
                    ),
                    self.gen_slider,
                    ft.Divider(height=1, color=BORDER_COLOR),
                    ft.Checkbox(label="Minuscole (a-z)", value=self.gen_lowercase, on_change=lambda e: self._toggle_gen_opt("lower", e.control.value)),
                    ft.Checkbox(label="Maiuscole (A-Z)", value=self.gen_uppercase, on_change=lambda e: self._toggle_gen_opt("upper", e.control.value)),
                    ft.Checkbox(label="Numeri (0-9)", value=self.gen_digits, on_change=lambda e: self._toggle_gen_opt("digits", e.control.value)),
                    ft.Checkbox(label="Simboli (!@#...)", value=self.gen_symbols, on_change=lambda e: self._toggle_gen_opt("symbols", e.control.value)),
                    ft.Checkbox(label="Escludi caratteri ambigui (I, l, 1, O, 0)", value=self.gen_no_ambiguous, on_change=lambda e: self._toggle_gen_opt("ambiguous", e.control.value)),
                ],
            ),
        )

        btn_gen = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.AUTO_FIX_HIGH_ROUNDED, size=15, color=TEXT_WHITE),
                    ft.Text("Rigenera Nuova Password", color=TEXT_WHITE, weight=ft.FontWeight.W_600, size=13),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=8,
            ),
            bgcolor=PURPLE_PRIMARY,
            border_radius=12,
            height=40,
            alignment=ft.Alignment(0, 0),
            on_click=lambda _: self._on_regenerate_click(),
            ink=True,
        )

        return ft.Container(
            expand=True,
            content=ft.Column(
                spacing=8,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                controls=[
                    pwd_display,
                    strength_card,
                    options_card,
                    btn_gen,
                ],
            ),
        )

    def _update_generator_ui(self) -> None:
        """Update password display, strength indicator, and controls in-place without rebuilding."""
        self._generate_pwd()
        score, label, color_hex = evaluate_password_strength(self.generated_pwd_value)
        self.gen_pwd_text.value = self.generated_pwd_value or self.generator_error
        self.gen_pwd_text.color = ROSE_DANGER if self.generator_error else CYAN_ACCENT
        self.gen_strength_label.value = label
        self.gen_strength_label.color = color_hex
        self.gen_strength_bar.value = score
        self.gen_strength_bar.color = color_hex
        try:
            self.gen_pwd_text.update()
            self.gen_strength_label.update()
            self.gen_strength_bar.update()
        except Exception:
            pass

    def _on_length_slider_change(self, val: int) -> None:
        self.record_activity()
        self.gen_length = max(MIN_PASSWORD_LENGTH, min(MAX_PASSWORD_LENGTH, val))
        self.gen_length_input.value = str(self.gen_length)
        try:
            self.gen_length_input.update()
        except Exception:
            pass
        self._update_generator_ui()

    def _on_length_input_change(self, val_str: str) -> None:
        """Apply the typed length while it is in range, without correcting it yet.

        Clamping on every keystroke would rewrite the first digit of "20" to the
        minimum before the second one is typed, so out-of-range values are left
        alone until the field is committed.
        """
        self.record_activity()
        clean = "".join(c for c in val_str if c.isdigit())
        if not clean:
            return

        val = int(clean)
        if MIN_PASSWORD_LENGTH <= val <= MAX_PASSWORD_LENGTH:
            self.gen_length = val
            self.gen_slider.value = float(val)
            try:
                self.gen_slider.update()
            except Exception:
                pass
            self._update_generator_ui()

    def _commit_length_input(self) -> None:
        """On blur or submit, clamp whatever is in the field and explain the change."""
        self.record_activity()
        raw = self.gen_length_input.value or ""
        clean = "".join(c for c in raw if c.isdigit())
        requested = int(clean) if clean else self.gen_length
        val = max(MIN_PASSWORD_LENGTH, min(MAX_PASSWORD_LENGTH, requested))

        if val != requested or not clean:
            self._show_snackbar(
                f"La lunghezza deve essere tra {MIN_PASSWORD_LENGTH} e "
                f"{MAX_PASSWORD_LENGTH}: impostata a {val}",
                is_error=True,
            )

        self.gen_length = val
        self.gen_slider.value = float(val)
        self.gen_length_input.value = str(val)
        for control in (self.gen_slider, self.gen_length_input):
            try:
                control.update()
            except Exception:
                pass
        self._update_generator_ui()

    def _on_regenerate_click(self) -> None:
        self.record_activity()
        self._update_generator_ui()

    def _toggle_gen_opt(self, opt_name: str, val: bool) -> None:
        self.record_activity()
        if opt_name == "lower":
            self.gen_lowercase = val
        elif opt_name == "upper":
            self.gen_uppercase = val
        elif opt_name == "digits":
            self.gen_digits = val
        elif opt_name == "symbols":
            self.gen_symbols = val
        elif opt_name == "ambiguous":
            self.gen_no_ambiguous = val
        self._update_generator_ui()

    def _generate_pwd(self, update_ui: bool = False) -> None:
        self.record_activity()
        try:
            opts = PasswordOptions(
                length=self.gen_length,
                use_lowercase=self.gen_lowercase,
                use_uppercase=self.gen_uppercase,
                use_digits=self.gen_digits,
                use_symbols=self.gen_symbols,
                exclude_ambiguous=self.gen_no_ambiguous,
            )
            self.generated_pwd_value = generate_password(opts)
            self.generator_error = ""
        except ValueError:
            # Unchecking every character set used to blank the password with no
            # explanation. Keep the reason so the UI can show it, in the UI's
            # language rather than the generator's.
            self.generated_pwd_value = ""
            if not any(
                (self.gen_lowercase, self.gen_uppercase, self.gen_digits, self.gen_symbols)
            ):
                self.generator_error = "Seleziona almeno un set di caratteri"
            else:
                self.generator_error = (
                    f"Lunghezza non valida: usa un valore tra "
                    f"{MIN_PASSWORD_LENGTH} e {MAX_PASSWORD_LENGTH}"
                )

        if update_ui:
            self._update_generator_ui()

    def _lock_vault(self) -> None:
        self._hotkey.stop()
        self.account_store.close()
        self.auth_mode = "login"
        self.current_username = ""
        self._current_key = None
        self.autotype_enabled = False
        self.revealed_ids.clear()
        self.render()


# Alias for backwards compatibility
LuxCipherApp = LuxCipherFletApp


def main() -> None:
    ft.run(lambda page: LuxCipherFletApp(page))


if __name__ == "__main__":
    main()

