"""Tkinter desktop interface for LuxCipher with SQLCipher encrypted storage."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from luxcipher.account_store import AccountStore, AccountStoreError
from luxcipher.auth import derive_master_key
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

        self.title("LuxCipher - Password Manager")
        self.geometry("560x560")
        self.minsize(500, 480)

        # Auth form variables
        self.setup_username = tk.StringVar(value="")
        self.setup_master_password = tk.StringVar(value="")
        self.setup_confirm_password = tk.StringVar(value="")
        self.login_username = tk.StringVar(value="")
        self.login_master_password = tk.StringVar(value="")
        self.current_username = tk.StringVar(value="")
        self.auth_status = tk.StringVar(value="")

        # Vault entry fields
        self.new_service = tk.StringVar(value="")
        self.new_username = tk.StringVar(value="")
        self.new_password = tk.StringVar(value="")
        self.vault_status = tk.StringVar(value="")
        self.show_vault_passwords = tk.BooleanVar(value=False)

        # Password generator fields
        self.length = tk.IntVar(value=20)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        self.generated_password = tk.StringVar(value="")
        self.generator_status = tk.StringVar(value="Pronto")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.container = ttk.Frame(self, padding=16)
        self.container.grid(row=0, column=0, sticky="nsew")
        self.container.columnconfigure(0, weight=1)

        self._show_auth_screen()

    @property
    def _salt_path(self):
        return self.account_store.path.with_name("vault.salt")

    def _show_auth_screen(self, preferred_mode: str | None = None) -> None:
        self._clear_container()
        self.auth_status.set("")

        if preferred_mode == "setup" or (preferred_mode is None and not self.account_store.exists()):
            self._build_setup_screen()
        else:
            self._build_login_screen()

    def _toggle_password_visibility(self, entry: ttk.Entry, button: ttk.Button) -> None:
        if entry.cget("show") == "*":
            entry.configure(show="")
            button.configure(text="Nascondi")
        else:
            entry.configure(show="*")
            button.configure(text="Mostra")

    def _build_setup_screen(self) -> None:
        self._clear_container()
        self._configure_container_columns()

        title = ttk.Label(
            self.container,
            text="Crea Account",
            font=("Segoe UI", 14, "bold"),
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))

        desc = ttk.Label(
            self.container,
            text="Imposta un Nome Utente e una Master Password per il tuo account.",
            font=("Segoe UI", 9),
            foreground="#555555",
        )
        desc.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 14))

        ttk.Label(self.container, text="Nome Utente:").grid(
            row=2,
            column=0,
            sticky="w",
            pady=(6, 0),
        )
        username_entry = ttk.Entry(
            self.container,
            textvariable=self.setup_username,
            width=30,
        )
        username_entry.grid(row=2, column=1, sticky="ew", pady=(6, 0))

        ttk.Label(self.container, text="Master Password:").grid(
            row=3,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        pwd_box1 = ttk.Frame(self.container)
        pwd_box1.grid(row=3, column=1, sticky="ew", pady=(8, 0))
        pwd_box1.columnconfigure(0, weight=1)

        password_entry = ttk.Entry(
            pwd_box1,
            textvariable=self.setup_master_password,
            show="*",
            width=22,
        )
        password_entry.grid(row=0, column=0, sticky="ew")
        btn_show1 = ttk.Button(
            pwd_box1,
            text="Mostra",
            width=8,
            command=lambda: self._toggle_password_visibility(password_entry, btn_show1),
        )
        btn_show1.grid(row=0, column=1, padx=(6, 0))

        ttk.Label(self.container, text="Conferma Password:").grid(
            row=4,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        pwd_box2 = ttk.Frame(self.container)
        pwd_box2.grid(row=4, column=1, sticky="ew", pady=(8, 0))
        pwd_box2.columnconfigure(0, weight=1)

        confirm_entry = ttk.Entry(
            pwd_box2,
            textvariable=self.setup_confirm_password,
            show="*",
            width=22,
        )
        confirm_entry.grid(row=0, column=0, sticky="ew")
        btn_show2 = ttk.Button(
            pwd_box2,
            text="Mostra",
            width=8,
            command=lambda: self._toggle_password_visibility(confirm_entry, btn_show2),
        )
        btn_show2.grid(row=0, column=1, padx=(6, 0))

        ttk.Button(self.container, text="Crea Account", command=self._create_account).grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(16, 0),
        )

        ttk.Button(
            self.container,
            text="Hai già un account? Accedi",
            command=lambda: self._show_auth_screen("login"),
        ).grid(
            row=6,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(8, 0),
        )

        status_lbl = ttk.Label(
            self.container,
            textvariable=self.auth_status,
            foreground="red",
            wraplength=380,
        )
        status_lbl.grid(row=7, column=0, columnspan=2, sticky="w", pady=(10, 0))

        for entry in (username_entry, password_entry, confirm_entry):
            entry.bind("<Return>", lambda _event: self._create_account())

        username_entry.focus_set()

    def _build_login_screen(self) -> None:
        self._clear_container()
        self._configure_container_columns()

        title = ttk.Label(
            self.container,
            text="Accedi a LuxCipher",
            font=("Segoe UI", 14, "bold"),
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))

        desc = ttk.Label(
            self.container,
            text="Inserisci le tue credenziali per accedere al Vault.",
            font=("Segoe UI", 9),
            foreground="#555555",
        )
        desc.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 14))

        ttk.Label(self.container, text="Nome Utente:").grid(
            row=2,
            column=0,
            sticky="w",
            pady=(6, 0),
        )
        username_entry = ttk.Entry(
            self.container,
            textvariable=self.login_username,
            width=30,
        )
        username_entry.grid(row=2, column=1, sticky="ew", pady=(6, 0))

        ttk.Label(self.container, text="Master Password:").grid(
            row=3,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        pwd_box = ttk.Frame(self.container)
        pwd_box.grid(row=3, column=1, sticky="ew", pady=(8, 0))
        pwd_box.columnconfigure(0, weight=1)

        password_entry = ttk.Entry(
            pwd_box,
            textvariable=self.login_master_password,
            show="*",
            width=22,
        )
        password_entry.grid(row=0, column=0, sticky="ew")
        btn_show = ttk.Button(
            pwd_box,
            text="Mostra",
            width=8,
            command=lambda: self._toggle_password_visibility(password_entry, btn_show),
        )
        btn_show.grid(row=0, column=1, padx=(6, 0))

        password_entry.bind("<Return>", lambda _event: self._unlock())

        ttk.Button(self.container, text="Accedi", command=self._unlock).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(16, 0),
        )

        ttk.Button(
            self.container,
            text="Non hai un account? Registrati",
            command=lambda: self._show_auth_screen("setup"),
        ).grid(
            row=5,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(8, 0),
        )

        status_lbl = ttk.Label(
            self.container,
            textvariable=self.auth_status,
            foreground="red",
            wraplength=380,
        )
        status_lbl.grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 0))

        username_entry.focus_set()

    def _create_account(self) -> None:
        username = self.setup_username.get().strip()
        master_password = self.setup_master_password.get()
        confirm_password = self.setup_confirm_password.get()

        if not username:
            self.auth_status.set("Inserisci un nome utente")
            return

        if not master_password:
            self.auth_status.set("Inserisci una master password")
            return

        if master_password != confirm_password:
            self.auth_status.set("Le master password non coincidono")
            return

        try:
            master_key = derive_master_key(master_password, salt_path=self._salt_path)
            self.account_store.open(master_key)
            self.account_store.set_account_username(username)
        except (AccountStoreError, TypeError, ValueError) as error:
            self.auth_status.set(str(error))
            return

        self.current_username.set(username)
        self._clear_auth_secrets()
        self._show_vault_screen()

    def _unlock(self) -> None:
        username = self.login_username.get().strip()
        master_password = self.login_master_password.get()

        if not username:
            self.auth_status.set("Inserisci il nome utente")
            return

        if not master_password:
            self.auth_status.set("Inserisci la master password")
            return

        try:
            master_key = derive_master_key(master_password, salt_path=self._salt_path)
            self.account_store.open(master_key)

            # Verifica che il nome utente coincida
            saved_username = self.account_store.get_account_username()
            if saved_username is not None and saved_username.strip().lower() != username.lower():
                self.account_store.close()
                self.auth_status.set("Nome Utente o Master Password errati")
                return

        except ValueError as error:
            self.auth_status.set(str(error))
            return
        except Exception as error:
            self.auth_status.set(f"Errore di accesso: {error}")
            return

        self.current_username.set(username)
        self._clear_auth_secrets()
        self._show_vault_screen()

    def _show_vault_screen(self) -> None:
        self._clear_container()
        self.container.columnconfigure(0, weight=1)
        self.container.columnconfigure(1, weight=0)

        # Header with username & Disconnect Button
        header = ttk.Frame(self.container)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)

        user_display = self.current_username.get()
        title = ttk.Label(header, text=f"Account: {user_display}", font=("Segoe UI", 13, "bold"))
        title.grid(row=0, column=0, sticky="w")

        lock_btn = ttk.Button(header, text="Disconnetti", command=self._lock)
        lock_btn.grid(row=0, column=1, sticky="e")

        # Tabs for Vault and Generator
        notebook = ttk.Notebook(self.container)
        notebook.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.container.rowconfigure(1, weight=1)

        tab_accounts = ttk.Frame(notebook, padding=10)
        tab_generator = ttk.Frame(notebook, padding=10)

        notebook.add(tab_accounts, text="Credenziali Vault")
        notebook.add(tab_generator, text="Generatore Password")

        self._build_accounts_tab(tab_accounts)
        self._build_generator_tab(tab_generator)

    def _build_accounts_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

        # Treeview list
        columns = ("id", "service", "username", "password")
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=8)
        self.tree.heading("id", text="#")
        self.tree.heading("service", text="Servizio")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")

        self.tree.column("id", width=35, anchor="center")
        self.tree.column("service", width=120)
        self.tree.column("username", width=140)
        self.tree.column("password", width=140)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Table actions: copy and show/hide
        tbl_actions = ttk.Frame(parent)
        tbl_actions.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        tbl_actions.columnconfigure(0, weight=1)
        tbl_actions.columnconfigure(1, weight=1)

        ttk.Button(
            tbl_actions,
            text="Copia Password selezionata",
            command=self._copy_selected_password,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 4))

        self.btn_toggle_tbl_pwd = ttk.Button(
            tbl_actions,
            text="Mostra Password in tabella",
            command=self._toggle_table_passwords,
        )
        self.btn_toggle_tbl_pwd.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        # Add account form
        form = ttk.LabelFrame(parent, text="Aggiungi Credenziale", padding=8)
        form.grid(row=2, column=0, sticky="ew", pady=(0, 6))
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Servizio:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self.new_service).grid(row=0, column=1, sticky="ew", padx=4, pady=2)

        ttk.Label(form, text="Username:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self.new_username).grid(row=1, column=1, sticky="ew", padx=4, pady=2)

        ttk.Label(form, text="Password:").grid(row=2, column=0, sticky="w", pady=2)
        pwd_box = ttk.Frame(form)
        pwd_box.grid(row=2, column=1, sticky="ew", padx=4, pady=2)
        pwd_box.columnconfigure(0, weight=1)

        self.new_pwd_entry = ttk.Entry(pwd_box, textvariable=self.new_password, show="*")
        self.new_pwd_entry.grid(row=0, column=0, sticky="ew")

        btn_show_new = ttk.Button(
            pwd_box,
            text="Mostra",
            width=7,
            command=lambda: self._toggle_password_visibility(self.new_pwd_entry, btn_show_new),
        )
        btn_show_new.grid(row=0, column=1, padx=(4, 2))

        ttk.Button(pwd_box, text="Usa generata", command=self._use_generated_in_form).grid(
            row=0, column=2, padx=(2, 0)
        )

        ttk.Button(form, text="Salva nel Vault", command=self._add_account).grid(
            row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0)
        )

        status_lbl = ttk.Label(parent, textvariable=self.vault_status, foreground="#333333")
        status_lbl.grid(row=3, column=0, sticky="w")

        self._refresh_accounts()

    def _toggle_table_passwords(self) -> None:
        self.show_vault_passwords.set(not self.show_vault_passwords.get())
        if self.show_vault_passwords.get():
            self.btn_toggle_tbl_pwd.configure(text="Nascondi Password in tabella")
        else:
            self.btn_toggle_tbl_pwd.configure(text="Mostra Password in tabella")
        self._refresh_accounts()

    def _build_generator_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=0)
        parent.columnconfigure(1, weight=1)

        password_entry = ttk.Entry(
            parent,
            textvariable=self.generated_password,
            state="readonly",
            font=("Consolas", 11),
        )
        password_entry.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(4, 10))

        ttk.Label(parent, text="Lunghezza:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        length_input = ttk.Spinbox(
            parent,
            from_=MIN_PASSWORD_LENGTH,
            to=MAX_PASSWORD_LENGTH,
            textvariable=self.length,
            width=8,
            command=self._generate,
        )
        length_input.grid(row=1, column=1, sticky="e", pady=(4, 0))
        length_input.bind("<Return>", lambda _event: self._generate())

        options = ttk.LabelFrame(parent, text="Includi caratteri", padding=8)
        options.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        ttk.Checkbutton(options, text="minuscole (a-z)", variable=self.use_lowercase, command=self._generate).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Checkbutton(options, text="maiuscole (A-Z)", variable=self.use_uppercase, command=self._generate).grid(
            row=1, column=0, sticky="w"
        )
        ttk.Checkbutton(options, text="numeri (0-9)", variable=self.use_digits, command=self._generate).grid(
            row=2, column=0, sticky="w"
        )
        ttk.Checkbutton(options, text="simboli (!@#...)", variable=self.use_symbols, command=self._generate).grid(
            row=3, column=0, sticky="w"
        )
        ttk.Checkbutton(
            options,
            text="escludi ambigui (I, l, 1, O, 0)",
            variable=self.exclude_ambiguous,
            command=self._generate,
        ).grid(row=4, column=0, sticky="w", pady=(4, 0))

        actions = ttk.Frame(parent)
        actions.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)

        ttk.Button(actions, text="Genera Password", command=self._generate).grid(
            row=0, column=0, sticky="ew", padx=(0, 4)
        )
        ttk.Button(actions, text="Copia negli Appunti", command=self._copy_password).grid(
            row=0, column=1, sticky="ew", padx=(4, 0)
        )

        status = ttk.Label(parent, textvariable=self.generator_status)
        status.grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        self._generate()

    def _refresh_accounts(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.account_store.is_open():
            return

        try:
            accounts = self.account_store.get_all_accounts()
            show_plain = self.show_vault_passwords.get()
            for acc in accounts:
                row_id, service, uname, pwd = acc[0], acc[1], acc[2], acc[3]
                display_pwd = pwd if show_plain else ("•" * min(len(pwd), 12))
                self.tree.insert("", "end", values=(row_id, service, uname, display_pwd), tags=(pwd,))
            self.vault_status.set(f"{len(accounts)} credenziali caricate.")
        except Exception as error:
            self.vault_status.set(f"Errore lettura vault: {error}")

    def _add_account(self) -> None:
        service = self.new_service.get().strip()
        username = self.new_username.get().strip()
        password = self.new_password.get()

        if not service or not username or not password:
            self.vault_status.set("Tutti i campi (servizio, username, password) sono obbligatori.")
            return

        try:
            self.account_store.add_account(service, username, password)
            self.new_service.set("")
            self.new_username.set("")
            self.new_password.set("")
            self.vault_status.set("Credenziale salvata con successo!")
            self._refresh_accounts()
        except Exception as error:
            self.vault_status.set(f"Errore durante il salvataggio: {error}")

    def _copy_selected_password(self) -> None:
        selected = self.tree.selection()
        if not selected:
            self.vault_status.set("Seleziona una riga dalla tabella per copiare la password.")
            return

        item = self.tree.item(selected[0])
        tags = item.get("tags", [])
        if tags:
            pwd = str(tags[0])
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self.vault_status.set("Password copiata negli appunti!")
            return

        values = item.get("values", [])
        if len(values) >= 4:
            pwd = str(values[3])
            self.clipboard_clear()
            self.clipboard_append(pwd)
            self.vault_status.set("Password copiata negli appunti!")

    def _use_generated_in_form(self) -> None:
        pwd = self.generated_password.get()
        if not pwd:
            self._generate()
            pwd = self.generated_password.get()
        self.new_password.set(pwd)
        self.vault_status.set("Password generata inserita nel modulo.")

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
        self.account_store.close()
        self.generated_password.set("")
        self.generator_status.set("Disconnesso")
        self._clear_auth_secrets()
        self._show_auth_screen("login")

    def _clear_auth_secrets(self) -> None:
        self.setup_username.set("")
        self.setup_master_password.set("")
        self.setup_confirm_password.set("")
        self.login_username.set("")
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
