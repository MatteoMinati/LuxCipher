"""Tkinter desktop interface for LuxCipher."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from luxcipher.account_store import AccountStore, AccountStoreError
from luxcipher.auth import LocalAccount
from luxcipher.password_generator import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordOptions,
    generate_password,
)


class LuxCipherApp(tk.Tk):
    def __init__(self, account_store: AccountStore | None = None) -> None:
        super().__init__()

        self.account_store = account_store or AccountStore.default()
        self.account: LocalAccount | None = None

        self.title("LuxCipher")
        self.resizable(False, False)

        self.setup_username = tk.StringVar(value="")
        self.setup_master_password = tk.StringVar(value="")
        self.setup_confirm_password = tk.StringVar(value="")
        self.login_master_password = tk.StringVar(value="")
        self.auth_status = tk.StringVar(value="")

        self.length = tk.IntVar(value=20)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        self.generated_password = tk.StringVar(value="")
        self.generator_status = tk.StringVar(value="Pronto")

        self.columnconfigure(0, weight=1)
        self.container = ttk.Frame(self, padding=16)
        self.container.grid(row=0, column=0, sticky="nsew")

        self._show_auth_screen()

    def _show_auth_screen(self) -> None:
        self._clear_container()
        self.auth_status.set("")

        if not self.account_store.exists():
            self._build_setup_screen()
            return

        try:
            self.account = self.account_store.load()
        except AccountStoreError as error:
            self._build_account_error_screen(str(error))
            return

        self._build_login_screen()

    def _build_setup_screen(self) -> None:
        self._configure_container_columns()

        title = ttk.Label(
            self.container,
            text="Crea account locale",
            font=("Segoe UI", 14, "bold"),
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w")

        ttk.Label(self.container, text="Username").grid(row=1, column=0, sticky="w", pady=(14, 0))
        username_entry = ttk.Entry(self.container, textvariable=self.setup_username, width=34)
        username_entry.grid(row=1, column=1, sticky="ew", pady=(14, 0))

        ttk.Label(self.container, text="Master password").grid(
            row=2,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        password_entry = ttk.Entry(
            self.container,
            textvariable=self.setup_master_password,
            show="*",
            width=34,
        )
        password_entry.grid(row=2, column=1, sticky="ew", pady=(8, 0))

        ttk.Label(self.container, text="Conferma").grid(row=3, column=0, sticky="w", pady=(8, 0))
        confirm_entry = ttk.Entry(
            self.container,
            textvariable=self.setup_confirm_password,
            show="*",
            width=34,
        )
        confirm_entry.grid(row=3, column=1, sticky="ew", pady=(8, 0))

        ttk.Button(self.container, text="Crea account", command=self._create_account).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(14, 0),
        )

        ttk.Label(self.container, textvariable=self.auth_status).grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(10, 0),
        )

        for entry in (username_entry, password_entry, confirm_entry):
            entry.bind("<Return>", lambda _event: self._create_account())

        username_entry.focus_set()

    def _build_login_screen(self) -> None:
        self._configure_container_columns()
        username = self.account.username if self.account else ""

        title = ttk.Label(
            self.container,
            text="Sblocca LuxCipher",
            font=("Segoe UI", 14, "bold"),
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w")

        ttk.Label(self.container, text="Account").grid(row=1, column=0, sticky="w", pady=(14, 0))
        ttk.Label(self.container, text=username).grid(row=1, column=1, sticky="w", pady=(14, 0))

        ttk.Label(self.container, text="Master password").grid(
            row=2,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        password_entry = ttk.Entry(
            self.container,
            textvariable=self.login_master_password,
            show="*",
            width=34,
        )
        password_entry.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        password_entry.bind("<Return>", lambda _event: self._unlock())

        ttk.Button(self.container, text="Sblocca", command=self._unlock).grid(
            row=3,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(14, 0),
        )

        ttk.Label(self.container, textvariable=self.auth_status).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(10, 0),
        )

        password_entry.focus_set()

    def _build_account_error_screen(self, message: str) -> None:
        self._configure_container_columns()
        ttk.Label(
            self.container,
            text="Account locale non leggibile",
            font=("Segoe UI", 14, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(self.container, text=message).grid(row=1, column=0, sticky="w", pady=(12, 0))
        ttk.Button(self.container, text="Riprova", command=self._show_auth_screen).grid(
            row=2,
            column=0,
            sticky="ew",
            pady=(14, 0),
        )

    def _create_account(self) -> None:
        master_password = self.setup_master_password.get()
        confirm_password = self.setup_confirm_password.get()

        if master_password != confirm_password:
            self.auth_status.set("Le master password non coincidono")
            return

        try:
            account = LocalAccount.create(
                username=self.setup_username.get(),
                master_password=master_password,
            )
            self.account_store.save(account)
        except (AccountStoreError, TypeError, ValueError) as error:
            self.auth_status.set(str(error))
            return

        self.account = account
        self._clear_auth_secrets()
        self._show_generator_screen()

    def _unlock(self) -> None:
        if self.account is None:
            self.auth_status.set("Account locale non caricato")
            return

        if not self.account.verify_master_password(self.login_master_password.get()):
            self.auth_status.set("Master password non valida")
            return

        self._clear_auth_secrets()
        self._show_generator_screen()

    def _show_generator_screen(self) -> None:
        self._clear_container()
        self._configure_container_columns()

        title = ttk.Label(self.container, text="Generatore password", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=2, sticky="w")

        username = self.account.username if self.account else ""
        ttk.Label(self.container, text=f"Account locale: {username}").grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(4, 0),
        )

        password_entry = ttk.Entry(
            self.container,
            textvariable=self.generated_password,
            width=36,
            state="readonly",
            font=("Consolas", 11),
        )
        password_entry.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 8))

        length_label = ttk.Label(self.container, text="Lunghezza")
        length_label.grid(row=3, column=0, sticky="w", pady=(4, 0))

        length_input = ttk.Spinbox(
            self.container,
            from_=MIN_PASSWORD_LENGTH,
            to=MAX_PASSWORD_LENGTH,
            textvariable=self.length,
            width=8,
            command=self._generate,
        )
        length_input.grid(row=3, column=1, sticky="e", pady=(4, 0))
        length_input.bind("<Return>", lambda _event: self._generate())

        options = ttk.LabelFrame(self.container, text="Caratteri", padding=10)
        options.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(12, 0))

        ttk.Checkbutton(
            options,
            text="minuscole",
            variable=self.use_lowercase,
            command=self._generate,
        ).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(
            options,
            text="maiuscole",
            variable=self.use_uppercase,
            command=self._generate,
        ).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(
            options,
            text="numeri",
            variable=self.use_digits,
            command=self._generate,
        ).grid(row=2, column=0, sticky="w")
        ttk.Checkbutton(
            options,
            text="simboli",
            variable=self.use_symbols,
            command=self._generate,
        ).grid(row=3, column=0, sticky="w")
        ttk.Checkbutton(
            options,
            text="evita ambigui",
            variable=self.exclude_ambiguous,
            command=self._generate,
        ).grid(row=4, column=0, sticky="w", pady=(6, 0))

        actions = ttk.Frame(self.container)
        actions.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)
        actions.columnconfigure(2, weight=1)

        ttk.Button(actions, text="Genera", command=self._generate).grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(0, 4),
        )
        ttk.Button(actions, text="Copia", command=self._copy_password).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=4,
        )
        ttk.Button(actions, text="Blocca", command=self._lock).grid(
            row=0,
            column=2,
            sticky="ew",
            padx=(4, 0),
        )

        status = ttk.Label(self.container, textvariable=self.generator_status)
        status.grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 0))

        self._generate()

    def _generate(self) -> None:
        try:
            options = PasswordOptions(
                length=self.length.get(),
                use_lowercase=self.use_lowercase.get(),
                use_uppercase=self.use_uppercase.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                exclude_ambiguous=self.exclude_ambiguous.get(),
            )
            self.generated_password.set(generate_password(options))
            self.generator_status.set("Password generata")
        except (TypeError, ValueError, tk.TclError) as error:
            self.generated_password.set("")
            self.generator_status.set(str(error))

    def _copy_password(self) -> None:
        password = self.generated_password.get()
        if not password:
            self.generator_status.set("Nessuna password da copiare")
            return

        self.clipboard_clear()
        self.clipboard_append(password)
        self.generator_status.set("Password copiata negli appunti")

    def _lock(self) -> None:
        self.generated_password.set("")
        self.generator_status.set("Bloccato")
        self._clear_auth_secrets()
        self._show_auth_screen()

    def _clear_auth_secrets(self) -> None:
        self.setup_master_password.set("")
        self.setup_confirm_password.set("")
        self.login_master_password.set("")

    def _clear_container(self) -> None:
        for child in self.container.winfo_children():
            child.destroy()

    def _configure_container_columns(self) -> None:
        self.container.columnconfigure(0, weight=0)
        self.container.columnconfigure(1, weight=1)


def main() -> None:
    app = LuxCipherApp()
    app.mainloop()
