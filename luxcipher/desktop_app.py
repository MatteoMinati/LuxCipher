"""Modern Minimal Pop desktop interface for LuxCipher password manager with Flet."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
from pathlib import Path
import sys
from typing import Any

import flet as ft

from luxcipher.account_store import AccountStore, AccountStoreError
from luxcipher.auth import derive_master_key
from luxcipher.password_generator import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordOptions,
    generate_password,
)

# Colors
BG_ROOT = "#0F101A"
BG_CARD = "#171927"
BG_INPUT = "#1F2236"
BORDER_COLOR = "#2C314E"
BORDER_FOCUS = "#7C3AED"

PURPLE_PRIMARY = "#7C3AED"       # Vibrant Electric Violet / Purple
PURPLE_HOVER = "#8B5CF6"
CYAN_ACCENT = "#06B6D4"
EMERALD_ACCENT = "#10B981"
ROSE_DANGER = "#F43F5E"
TEXT_WHITE = "#FFFFFF"
TEXT_MUTED = "#9095AC"
TEXT_SUBTLE = "#646A85"
BTN_DARK = "#262A42"


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
    def __init__(self, page: ft.Page, account_store: AccountStore | None = None) -> None:
        self.page = page
        self.account_store = account_store or AccountStore.default()
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

        # References for test/direct access
        self.auth_username_field = ft.TextField()
        self.auth_password_field = ft.TextField()
        self.auth_confirm_field = ft.TextField()
        self.new_service_field = ft.TextField()
        self.new_user_field = ft.TextField()
        self.new_pwd_field = ft.TextField()

        self._configure_page()
        self._generate_pwd()
        self.render()

    @property
    def _salt_path(self) -> Path:
        return self.account_store.path.with_name("vault.salt")

    def _configure_page(self) -> None:
        self.page.title = "LuxCipher — Secure Password Vault"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = BG_ROOT
        self.page.padding = 0

        try:
            self.page.window.title_bar_hidden = True
            self.page.window.title_bar_buttons_hidden = True
            self.page.window.frameless = True
            self.page.window.width = 540
            self.page.window.height = 700
            self.page.window.min_width = 480
            self.page.window.min_height = 620
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
            bgcolor="#121422",
            padding=make_padding(horizontal=16, vertical=8),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.WindowDragArea(
                        expand=True,
                        content=ft.Row(
                            spacing=8,
                            controls=[
                                ft.Icon(ft.Icons.LOCK_ROUNDED, color="#A78BFA", size=18),
                                ft.Text("LuxCipher", weight=ft.FontWeight.BOLD, size=13, color=TEXT_WHITE),
                            ],
                        ),
                    ),
                    ft.Row(
                        spacing=2,
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
        try:
            self.page.window.minimized = True
            self.page.window.update()
        except Exception:
            try:
                self.page.update()
            except Exception:
                pass

    def _close_window(self) -> None:
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
        try:
            self.page.snack_bar = ft.SnackBar(
                content=ft.Text(message, color=TEXT_WHITE, weight=ft.FontWeight.W_500),
                bgcolor=ROSE_DANGER if is_error else EMERALD_ACCENT,
                duration=3000,
            )
            self.page.snack_bar.open = True
            self.page.update()
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

    # --- AUTH SCREENS (CENTERED) ---
    def _build_auth_view(self) -> ft.Control:
        is_login = self.auth_mode == "login"

        # Segmented switcher [ Accedi | Registrati ] centered
        btn_accedi = ft.Container(
            content=ft.Text("Accedi", color=TEXT_WHITE if is_login else TEXT_MUTED, weight=ft.FontWeight.BOLD, size=13),
            bgcolor=PURPLE_PRIMARY if is_login else ft.Colors.TRANSPARENT,
            border_radius=20,
            padding=make_padding(horizontal=28, vertical=8),
            on_click=lambda _: self._set_auth_mode("login"),
            ink=True,
        )
        btn_registrati = ft.Container(
            content=ft.Text("Registrati", color=TEXT_WHITE if not is_login else TEXT_MUTED, weight=ft.FontWeight.BOLD, size=13),
            bgcolor=PURPLE_PRIMARY if not is_login else ft.Colors.TRANSPARENT,
            border_radius=20,
            padding=make_padding(horizontal=28, vertical=8),
            on_click=lambda _: self._set_auth_mode("setup"),
            ink=True,
        )

        switcher_pill = ft.Container(
            bgcolor="#1B1D2E",
            border_radius=22,
            padding=3,
            content=ft.Row([btn_accedi, btn_registrati], tight=True),
        )

        switcher_row = ft.Row([switcher_pill], alignment=ft.MainAxisAlignment.CENTER)

        # Form fields
        self.auth_username_field = ft.TextField(
            hint_text="il tuo nome utente",
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=PURPLE_PRIMARY,
            border_radius=12,
            color=TEXT_WHITE,
            text_size=14,
            autofocus=True,
        )

        self.auth_password_field = ft.TextField(
            hint_text="master password",
            password=True,
            can_reveal_password=True,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=PURPLE_PRIMARY,
            border_radius=12,
            color=TEXT_WHITE,
            text_size=14,
            on_submit=lambda _: self._submit_auth(),
        )

        self.auth_confirm_field = ft.TextField(
            hint_text="conferma master password",
            password=True,
            can_reveal_password=True,
            bgcolor=BG_INPUT,
            border_color=BORDER_COLOR,
            focused_border_color=PURPLE_PRIMARY,
            border_radius=12,
            color=TEXT_WHITE,
            text_size=14,
            on_submit=lambda _: self._submit_auth(),
        )

        form_controls: list[ft.Control] = [
            ft.Row([ft.Text("NOME UTENTE", size=9, weight=ft.FontWeight.BOLD, color=TEXT_MUTED)], alignment=ft.MainAxisAlignment.START),
            self.auth_username_field,
            ft.Container(height=6),
            ft.Row([ft.Text("MASTER PASSWORD", size=9, weight=ft.FontWeight.BOLD, color=TEXT_MUTED)], alignment=ft.MainAxisAlignment.START),
            self.auth_password_field,
        ]

        if not is_login:
            form_controls.extend([
                ft.Container(height=6),
                ft.Row([ft.Text("CONFERMA PASSWORD", size=9, weight=ft.FontWeight.BOLD, color=TEXT_MUTED)], alignment=ft.MainAxisAlignment.START),
                self.auth_confirm_field,
            ])

        action_btn = ft.Container(
            content=ft.Text("Accedi" if is_login else "Crea account", color=TEXT_WHITE, weight=ft.FontWeight.BOLD, size=15),
            bgcolor=PURPLE_PRIMARY,
            border_radius=24,
            padding=make_padding(vertical=14),
            alignment=ft.Alignment(0, 0),
            on_click=lambda _: self._submit_auth(),
            ink=True,
        )

        bottom_link = ft.Row(
            alignment=ft.MainAxisAlignment.CENTER,
            controls=[
                ft.Text("Non hai un account? " if is_login else "Hai già un account? ", color=TEXT_MUTED, size=13),
                ft.Text(
                    "Crea un account" if is_login else "Accedi",
                    color=PURPLE_HOVER,
                    weight=ft.FontWeight.BOLD,
                    size=13,
                ),
            ],
        )

        bottom_link_container = ft.GestureDetector(
            content=bottom_link,
            on_tap=lambda _: self._set_auth_mode("setup" if is_login else "login"),
        )

        # Centered layout
        return ft.Container(
            alignment=ft.Alignment(0, 0),
            expand=True,
            padding=make_padding(horizontal=24, vertical=16),
            content=ft.Container(
                width=420,
                content=ft.Column(
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=10,
                    controls=[
                        switcher_row,
                        ft.Container(height=8),
                        ft.Text(
                            "Bentornato." if is_login else "Crea account.",
                            size=28,
                            weight=ft.FontWeight.BOLD,
                            color=TEXT_WHITE,
                            text_align=ft.TextAlign.CENTER,
                        ),
                        ft.Text(
                            "Accedi per gestire le tue credenziali cifrate." if is_login else "Inizia a proteggere le tue password in locale.",
                            size=13,
                            color=TEXT_MUTED,
                            text_align=ft.TextAlign.CENTER,
                        ),
                        ft.Container(height=12),
                        ft.Column(controls=form_controls, spacing=4),
                        ft.Container(height=14),
                        action_btn,
                        ft.Container(height=8),
                        bottom_link_container,
                    ],
                ),
            ),
        )

    def _set_auth_mode(self, mode: str) -> None:
        self.auth_mode = mode
        self.render()

    def _submit_auth(self) -> None:
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

    # --- VAULT UNLOCKED SCREEN ---
    def _build_vault_view(self) -> ft.Control:
        user_header = ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Row(
                    spacing=10,
                    controls=[
                        ft.Container(
                            content=ft.Icon(ft.Icons.PERSON_ROUNDED, color=TEXT_WHITE, size=20),
                            bgcolor="#282D46",
                            border_radius=20,
                            padding=8,
                        ),
                        ft.Column(
                            spacing=2,
                            alignment=ft.MainAxisAlignment.CENTER,
                            controls=[
                                ft.Text(self.current_username or "Utente", weight=ft.FontWeight.BOLD, size=15, color=TEXT_WHITE),
                                ft.Container(
                                    content=ft.Text("🔒 Vault Cifrato Attivo", size=9, weight=ft.FontWeight.BOLD, color=CYAN_ACCENT),
                                    bgcolor="#142B38",
                                    border_radius=10,
                                    padding=make_padding(horizontal=8, vertical=2),
                                ),
                            ],
                        ),
                    ],
                ),
                ft.Container(
                    content=ft.Row([ft.Icon(ft.Icons.LOGOUT_ROUNDED, color=TEXT_WHITE, size=14), ft.Text("Disconnetti", color=TEXT_WHITE, size=12, weight=ft.FontWeight.BOLD)], tight=True),
                    bgcolor=ROSE_DANGER,
                    border_radius=16,
                    padding=make_padding(horizontal=12, vertical=6),
                    on_click=lambda _: self._lock_vault(),
                    ink=True,
                ),
            ],
        )

        # Tab Segmented Switcher for Vault View
        is_vault_tab = self.active_tab == "vault"
        tab_btn_vault = ft.Container(
            content=ft.Row([ft.Icon(ft.Icons.STORAGE_ROUNDED, size=14, color=TEXT_WHITE if is_vault_tab else TEXT_MUTED), ft.Text("Credenziali Vault", color=TEXT_WHITE if is_vault_tab else TEXT_MUTED, weight=ft.FontWeight.BOLD, size=12)], tight=True),
            bgcolor=PURPLE_PRIMARY if is_vault_tab else ft.Colors.TRANSPARENT,
            border_radius=18,
            padding=make_padding(horizontal=16, vertical=8),
            on_click=lambda _: self._set_active_tab("vault"),
            ink=True,
        )
        tab_btn_gen = ft.Container(
            content=ft.Row([ft.Icon(ft.Icons.BOLT_ROUNDED, size=14, color=TEXT_WHITE if not is_vault_tab else TEXT_MUTED), ft.Text("Generatore Password", color=TEXT_WHITE if not is_vault_tab else TEXT_MUTED, weight=ft.FontWeight.BOLD, size=12)], tight=True),
            bgcolor=PURPLE_PRIMARY if not is_vault_tab else ft.Colors.TRANSPARENT,
            border_radius=18,
            padding=make_padding(horizontal=16, vertical=8),
            on_click=lambda _: self._set_active_tab("generator"),
            ink=True,
        )

        tab_switcher = ft.Container(
            bgcolor="#1B1D2E",
            border_radius=20,
            padding=3,
            content=ft.Row([tab_btn_vault, tab_btn_gen], tight=True),
        )

        content_body = self._build_credentials_tab() if is_vault_tab else self._build_generator_tab()

        return ft.Container(
            padding=make_padding(horizontal=24, vertical=14),
            expand=True,
            content=ft.Column(
                expand=True,
                spacing=12,
                controls=[
                    user_header,
                    tab_switcher,
                    ft.Divider(height=1, color=BORDER_COLOR),
                    content_body,
                ],
            ),
        )

    def _set_active_tab(self, tab_name: str) -> None:
        self.active_tab = tab_name
        self.render()

    def _build_credentials_tab(self) -> ft.Control:
        accounts = []
        if self.account_store.is_open():
            accounts = self.account_store.get_all_accounts()

        # Form fields for adding new account
        self.new_service_field = ft.TextField(hint_text="Servizio (es. Google, GitHub)", bgcolor=BG_INPUT, border_color=BORDER_COLOR, border_radius=10, text_size=12, color=TEXT_WHITE)
        self.new_user_field = ft.TextField(hint_text="Username o Email", bgcolor=BG_INPUT, border_color=BORDER_COLOR, border_radius=10, text_size=12, color=TEXT_WHITE)
        self.new_pwd_field = ft.TextField(hint_text="Password", password=True, can_reveal_password=True, bgcolor=BG_INPUT, border_color=BORDER_COLOR, border_radius=10, text_size=12, color=TEXT_WHITE, expand=True)

        btn_fill_pwd = ft.Container(
            content=ft.Row([ft.Icon(ft.Icons.BOLT_ROUNDED, size=14, color=CYAN_ACCENT), ft.Text("Generata", size=11, color=TEXT_WHITE, weight=ft.FontWeight.BOLD)], tight=True),
            bgcolor=BTN_DARK,
            border_radius=10,
            padding=make_padding(horizontal=10, vertical=8),
            on_click=lambda _: self._fill_generated_password(),
            ink=True,
        )

        add_form = ft.Container(
            bgcolor=BG_CARD,
            border_radius=14,
            border=make_border(BORDER_COLOR),
            padding=14,
            content=ft.Column(
                spacing=8,
                controls=[
                    ft.Text("➕ NUOVA CREDENZIALE", size=10, weight=ft.FontWeight.BOLD, color=CYAN_ACCENT),
                    self.new_service_field,
                    self.new_user_field,
                    ft.Row([self.new_pwd_field, btn_fill_pwd], spacing=6),
                    ft.Container(
                        content=ft.Row([ft.Icon(ft.Icons.SAVE_ROUNDED, size=16, color=TEXT_WHITE), ft.Text("Salva nel Vault Cifrato", color=TEXT_WHITE, weight=ft.FontWeight.BOLD, size=13)], alignment=ft.MainAxisAlignment.CENTER, tight=True),
                        bgcolor=PURPLE_PRIMARY,
                        border_radius=12,
                        padding=make_padding(vertical=10),
                        on_click=lambda _: self._add_account_entry(),
                        ink=True,
                    ),
                ],
            ),
        )

        # Accounts List Items
        account_cards: list[ft.Control] = []
        for acc in accounts:
            acc_id, srv, uname, pwd = acc[0], acc[1], acc[2], acc[3]
            display_pwd = pwd if self.show_passwords_in_table else ("•" * min(len(pwd), 12))

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
                                ft.Text(srv, weight=ft.FontWeight.BOLD, size=14, color=TEXT_WHITE),
                                ft.Text(uname, size=12, color=TEXT_MUTED),
                                ft.Text(display_pwd, size=12, color=CYAN_ACCENT, font_family="Consolas"),
                            ],
                        ),
                        ft.IconButton(
                            icon=ft.Icons.COPY_ROUNDED,
                            icon_color=EMERALD_ACCENT,
                            tooltip="Copia Password",
                            on_click=lambda _, p=pwd: self._copy_to_clipboard(p),
                        ),
                    ],
                ),
            )
            account_cards.append(card)

        cards_list = ft.ListView(
            controls=account_cards if account_cards else [
                ft.Container(
                    alignment=ft.Alignment(0, 0),
                    padding=20,
                    content=ft.Text("Nessuna credenziale salvata nel Vault", color=TEXT_MUTED, italic=True),
                )
            ],
            spacing=8,
            expand=True,
        )

        toggle_btn = ft.Container(
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.VISIBILITY_OFF if self.show_passwords_in_table else ft.Icons.VISIBILITY, size=14, color=TEXT_MUTED),
                    ft.Text("Nascondi Password" if self.show_passwords_in_table else "Mostra Password in elenco", size=11, color=TEXT_MUTED),
                ],
                tight=True,
            ),
            on_click=lambda _: self._toggle_table_passwords(),
        )

        return ft.Container(
            expand=True,
            content=ft.Column(
                expand=True,
                spacing=8,
                controls=[
                    add_form,
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text(f"{len(accounts)} Credenziali Salvate", weight=ft.FontWeight.BOLD, size=11, color=TEXT_MUTED),
                            toggle_btn,
                        ],
                    ),
                    cards_list,
                ],
            ),
        )

    def _toggle_table_passwords(self) -> None:
        self.show_passwords_in_table = not self.show_passwords_in_table
        self.render()

    def _copy_to_clipboard(self, text: str) -> None:
        # 1. Native Win32 copy (instant, 0 overhead, 0 external processes)
        set_system_clipboard(text)
        # 2. Also notify Flet clipboard if available
        try:
            self.page.clipboard.set(text)
        except Exception:
            pass
        self._show_snackbar("Password copiata negli appunti!")

    def _fill_generated_password(self) -> None:
        if not self.generated_pwd_value:
            self._generate_pwd()
        self.new_pwd_field.value = self.generated_pwd_value
        try:
            self.new_pwd_field.update()
        except Exception:
            pass
        self._show_snackbar("Password generata inserita nel form!")

    def _add_account_entry(self) -> None:
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
        pwd_display = ft.Container(
            bgcolor=BG_INPUT,
            border_radius=12,
            border=make_border(BORDER_COLOR),
            padding=14,
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Text(self.generated_pwd_value, font_family="Consolas", size=15, weight=ft.FontWeight.BOLD, color=CYAN_ACCENT),
                    ft.IconButton(
                        icon=ft.Icons.COPY_ROUNDED,
                        icon_color=EMERALD_ACCENT,
                        tooltip="Copia Password",
                        on_click=lambda _: self._copy_to_clipboard(self.generated_pwd_value),
                    ),
                ],
            ),
        )

        slider_len = ft.Slider(
            min=MIN_PASSWORD_LENGTH,
            max=MAX_PASSWORD_LENGTH,
            divisions=MAX_PASSWORD_LENGTH - MIN_PASSWORD_LENGTH,
            value=float(self.gen_length),
            label="{value}",
            active_color=PURPLE_PRIMARY,
            on_change=lambda e: self._on_length_change(int(e.control.value)),
        )

        options_card = ft.Container(
            bgcolor=BG_CARD,
            border_radius=14,
            border=make_border(BORDER_COLOR),
            padding=14,
            content=ft.Column(
                spacing=6,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Text("Lunghezza Password", weight=ft.FontWeight.BOLD, size=12, color=TEXT_WHITE),
                            ft.Text(f"{self.gen_length} caratteri", color=PURPLE_HOVER, weight=ft.FontWeight.BOLD, size=12),
                        ],
                    ),
                    slider_len,
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
            content=ft.Row([ft.Icon(ft.Icons.BOLT_ROUNDED, size=16, color=TEXT_WHITE), ft.Text("Genera Nuova Password", color=TEXT_WHITE, weight=ft.FontWeight.BOLD, size=14)], alignment=ft.MainAxisAlignment.CENTER, tight=True),
            bgcolor=PURPLE_PRIMARY,
            border_radius=16,
            padding=make_padding(vertical=12),
            on_click=lambda _: self._generate_pwd(update_ui=True),
            ink=True,
        )

        return ft.Container(
            expand=True,
            content=ft.Column(
                spacing=12,
                controls=[
                    pwd_display,
                    options_card,
                    btn_gen,
                ],
            ),
        )

    def _on_length_change(self, val: int) -> None:
        self.gen_length = val
        self._generate_pwd(update_ui=True)

    def _toggle_gen_opt(self, opt_name: str, val: bool) -> None:
        if opt_name == "lower": self.gen_lowercase = val
        elif opt_name == "upper": self.gen_uppercase = val
        elif opt_name == "digits": self.gen_digits = val
        elif opt_name == "symbols": self.gen_symbols = val
        elif opt_name == "ambiguous": self.gen_no_ambiguous = val
        self._generate_pwd(update_ui=True)

    def _generate_pwd(self, update_ui: bool = False) -> None:
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
            self.render()

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
