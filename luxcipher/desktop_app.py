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
from luxcipher.auth import (
    MIN_MASTER_PASSWORD_LENGTH,
    derive_master_key,
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


def make_padding(horizontal: int = 0, vertical: int = 0) -> ft.Padding:
    return ft.Padding(left=horizontal, top=vertical, right=horizontal, bottom=vertical)


def make_border(color: str = BORDER_COLOR, width: int = 1) -> ft.Border:
    side = ft.BorderSide(width, color)
    return ft.Border(top=side, right=side, bottom=side, left=side)


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

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002

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


class LuxCipherFletApp:
    def __init__(
        self,
        page: ft.Page,
        account_store: AccountStore | None = None,
        auto_lock_timeout: float = AUTO_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self.page = page
        self.account_store = account_store or AccountStore.default()
        self.auto_lock_timeout = auto_lock_timeout
        self.last_activity_time = time.time()
        self._running = True
        self.current_username = ""
        self.auth_mode = "setup" if not self.account_store.exists() else "login"
        self.active_tab = "vault"  # "vault" or "generator"
        self.show_passwords_in_table = False

        # Generator state
        self.gen_length = 20
        self.gen_lowercase = True
        self.gen_uppercase = True
        self.gen_digits = True
        self.gen_symbols = True
        self.gen_no_ambiguous = False
        self.generated_pwd_value = ""

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
        self.page.title = "LuxCipher — Secure Password Vault"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = BG_ROOT
        self.page.padding = 0

        try:
            self.page.on_keyboard_event = lambda _: self.record_activity()
        except Exception:
            pass

        try:
            self.page.window.title_bar_hidden = True
            self.page.window.title_bar_buttons_hidden = True
            self.page.window.frameless = True
            self.page.window.width = 520
            self.page.window.height = 760
            self.page.window.min_width = 460
            self.page.window.min_height = 680
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
            hwnd = ctypes.windll.user32.FindWindowW(None, "LuxCipher — Secure Password Vault")
            if hwnd:
                WM_CLOSE = 0x0010
                ctypes.windll.user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        except Exception:
            pass
        os._exit(0)

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
            except Exception as error:
                self._show_snackbar(str(error), is_error=True)
                return

            self.current_username = username
            self._show_snackbar("Account creato e Vault inizializzato!")
            self.render()

        else:  # login
            try:
                master_key = derive_master_key(password, salt_path=self._salt_path)
                self.account_store.open(master_key)

                saved_user = self.account_store.get_account_username()
                if saved_user and saved_user.strip().lower() != username.lower():
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
                    ft.Container(
                        content=ft.Row(
                            [
                                ft.Icon(ft.Icons.LOGOUT_ROUNDED, color="#FDA4AF", size=13),
                                ft.Text("Esci", color="#FDA4AF", size=11, weight=ft.FontWeight.W_600),
                            ],
                            spacing=4,
                            tight=True,
                        ),
                        bgcolor="#2A1520",
                        border=ft.Border(
                            top=ft.BorderSide(1, "#4C1D2A"),
                            right=ft.BorderSide(1, "#4C1D2A"),
                            bottom=ft.BorderSide(1, "#4C1D2A"),
                            left=ft.BorderSide(1, "#4C1D2A"),
                        ),
                        border_radius=14,
                        padding=make_padding(horizontal=10, vertical=5),
                        on_click=lambda _: self._lock_vault(),
                        ink=True,
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
            display_pwd = pwd if self.show_passwords_in_table else ("•" * min(len(pwd), 10))

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
                            controls=[
                                ft.Text(srv, weight=ft.FontWeight.W_700, size=13, color=TEXT_WHITE),
                                ft.Text(uname, size=11, color=TEXT_MUTED),
                                ft.Text(display_pwd, size=12, color=CYAN_ACCENT, font_family="Consolas"),
                            ],
                        ),
                        ft.Container(
                            content=ft.IconButton(
                                icon=ft.Icons.CONTENT_COPY_ROUNDED,
                                icon_color=EMERALD_ACCENT,
                                icon_size=16,
                                tooltip="Copia Password",
                                on_click=lambda _, p=pwd: self._copy_to_clipboard(p),
                            ),
                            bgcolor="#192C26",
                            border_radius=10,
                        ),
                    ],
                ),
            )
            account_cards.append(card)
        return account_cards

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

    def _copy_to_clipboard(self, text: str) -> None:
        self.record_activity()
        set_system_clipboard(text)
        try:
            self.page.clipboard.set(text)
        except Exception:
            pass
        self._show_snackbar("Password copiata negli appunti!")

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
        self.gen_pwd_text.value = self.generated_pwd_value
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
        self.gen_pwd_text.value = self.generated_pwd_value
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
        self.record_activity()
        clean = "".join(c for c in val_str if c.isdigit())
        if clean:
            val = int(clean)
            if MIN_PASSWORD_LENGTH <= val <= MAX_PASSWORD_LENGTH:
                self.gen_length = val
                self.gen_slider.value = float(val)
                try:
                    self.gen_slider.update()
                except Exception:
                    pass
                self._update_generator_ui()

    def _on_regenerate_click(self) -> None:
        self.record_activity()
        self._update_generator_ui()

    def _toggle_gen_opt(self, opt_name: str, val: bool) -> None:
        self.record_activity()
        if opt_name == "lower": self.gen_lowercase = val
        elif opt_name == "upper": self.gen_uppercase = val
        elif opt_name == "digits": self.gen_digits = val
        elif opt_name == "symbols": self.gen_symbols = val
        elif opt_name == "ambiguous": self.gen_no_ambiguous = val
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
        except Exception:
            self.generated_pwd_value = ""

        if update_ui:
            self._update_generator_ui()

    def _lock_vault(self) -> None:
        self.account_store.close()
        self.auth_mode = "login"
        self.current_username = ""
        self.render()


# Alias for backwards compatibility
LuxCipherApp = LuxCipherFletApp


def main() -> None:
    ft.app(target=lambda page: LuxCipherFletApp(page))


if __name__ == "__main__":
    main()

