"""Encrypted SQLCipher storage for LuxCipher accounts."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlcipher3 import dbapi2 as sqlite3


VAULT_DB_FILE = "vault.db"
APP_DIR_NAME = "LuxCipher"
ENV_HOME = "LUXCIPHER_HOME"


class AccountStoreError(RuntimeError):
    """Raised when vault storage operations fail."""


class AccountStore:
    """Manages encrypted SQLCipher database for accounts."""

    def __init__(self, path: str | Path = VAULT_DB_FILE) -> None:
        self.path = Path(path)
        self.conn: sqlite3.Connection | None = None

    @classmethod
    def default(cls) -> "AccountStore":
        return cls(default_db_path())

    def exists(self) -> bool:
        return self.path.is_file()

    def is_open(self) -> bool:
        return self.conn is not None

    def open(self, master_key: bytes) -> None:
        """Open or initialize the encrypted SQLCipher database using master_key."""
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError("master_key must be bytes.")

        self.close()
        key_hex = master_key.hex()

        if self.path.parent and str(self.path.parent) != ".":
            self.path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self.path))
        try:
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA key = \"x'{key_hex}'\";")
            cursor.execute("PRAGMA temp_store = MEMORY;")
            cursor.execute("PRAGMA secure_delete = ON;")
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );"""
            )
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL
                );"""
            )
            cursor.execute("SELECT count(*) FROM sqlite_master;")
            conn.commit()
        except (sqlite3.DatabaseError, MemoryError) as error:
            conn.close()
            raise ValueError("Master Password errata") from error
        except Exception:
            conn.close()
            raise

        self.conn = conn
        _restrict_to_current_user(self.path)

    def set_account_username(self, username: str) -> None:
        """Store the account username in the encrypted metadata table."""
        if self.conn is None:
            raise AccountStoreError("Database is not open.")
        if not isinstance(username, str):
            raise TypeError("username must be a string.")

        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('username', ?);",
            (username,),
        )
        self.conn.commit()

    def get_account_username(self) -> str | None:
        """Retrieve the account username from the encrypted metadata table."""
        if self.conn is None:
            raise AccountStoreError("Database is not open.")

        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = 'username';")
        row = cursor.fetchone()
        return str(row[0]) if row else None

    def add_account(self, service: str, username: str, password: str) -> None:
        """Insert account credentials into the encrypted vault."""
        if self.conn is None:
            raise AccountStoreError("Database is not open.")

        if not isinstance(service, str) or not isinstance(username, str) or not isinstance(password, str):
            raise TypeError("service, username, and password must be strings.")

        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO accounts (service, username, password) VALUES (?, ?, ?);",
            (service, username, password),
        )
        self.conn.commit()

    def get_all_accounts(self) -> list[tuple[Any, ...]]:
        """Retrieve all account credentials from the encrypted vault."""
        if self.conn is None:
            raise AccountStoreError("Database is not open.")

        cursor = self.conn.cursor()
        cursor.execute("SELECT id, service, username, password FROM accounts;")
        return cursor.fetchall()

    def search_accounts(self, query: str) -> list[tuple[Any, ...]]:
        """Search accounts by service name or username/email matching query."""
        if self.conn is None:
            raise AccountStoreError("Database is not open.")
        if not isinstance(query, str):
            raise TypeError("query must be a string.")

        term = query.strip()
        if not term:
            return self.get_all_accounts()

        pattern = f"%{term}%"
        cursor = self.conn.cursor()
        cursor.execute(
            """SELECT id, service, username, password FROM accounts
               WHERE service LIKE ? OR username LIKE ?;""",
            (pattern, pattern),
        )
        return cursor.fetchall()

    def close(self) -> None:
        """Close the database connection and release encryption context."""
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def __enter__(self) -> "AccountStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


def default_db_path() -> Path:
    configured_home = os.environ.get(ENV_HOME)
    if configured_home:
        return Path(configured_home).expanduser() / VAULT_DB_FILE

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / APP_DIR_NAME / VAULT_DB_FILE

    return Path.home() / f".{APP_DIR_NAME.lower()}" / VAULT_DB_FILE


def _restrict_to_current_user(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
