"""Tkinter desktop interface for LuxCipher."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from luxcipher.password_generator import MIN_PASSWORD_LENGTH, PasswordOptions, generate_password


class LuxCipherApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self.title("LuxCipher")
        self.resizable(False, False)

        self.length = tk.IntVar(value=20)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        self.generated_password = tk.StringVar(value="")
        self.status = tk.StringVar(value="Pronto")

        self._build_ui()
        self._generate()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)

        main = ttk.Frame(self, padding=16)
        main.grid(row=0, column=0, sticky="nsew")

        title = ttk.Label(main, text="Generatore password", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=2, sticky="w")

        password_entry = ttk.Entry(
            main,
            textvariable=self.generated_password,
            width=36,
            state="readonly",
            font=("Consolas", 11),
        )
        password_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 8))

        length_label = ttk.Label(main, text="Lunghezza")
        length_label.grid(row=2, column=0, sticky="w", pady=(4, 0))

        length_input = ttk.Spinbox(
            main,
            from_=MIN_PASSWORD_LENGTH,
            to=128,
            textvariable=self.length,
            width=8,
        )
        length_input.grid(row=2, column=1, sticky="e", pady=(4, 0))

        options = ttk.LabelFrame(main, text="Caratteri", padding=10)
        options.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))

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

        actions = ttk.Frame(main)
        actions.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)

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
            padx=(4, 0),
        )

        status = ttk.Label(main, textvariable=self.status)
        status.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))

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
            self.status.set("Password generata")
        except (ValueError, tk.TclError) as error:
            self.generated_password.set("")
            self.status.set(str(error))

    def _copy_password(self) -> None:
        password = self.generated_password.get()
        if not password:
            self.status.set("Nessuna password da copiare")
            return

        self.clipboard_clear()
        self.clipboard_append(password)
        self.status.set("Password copiata negli appunti")


def main() -> None:
    app = LuxCipherApp()
    app.mainloop()
