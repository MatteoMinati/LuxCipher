"""Encrypted SQLCipher storage for LuxCipher accounts."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
from typing import Any

from sqlcipher3 import dbapi2 as sqlite3


VAULT_DB_FILE = "vault.db"
VAULT_SALT_FILE = "vault.salt"
APP_DIR_NAME = "LuxCipher"
ENV_HOME = "LUXCIPHER_HOME"
LIKE_ESCAPE_CHARACTER = "\\"
SCHEMA_VERSION = 2

ACCOUNT_COLUMNS = "id, service, username, password, created_at, updated_at"


class AccountStoreError(RuntimeError):
    """Raised when vault storage operations fail."""


def utc_now_text() -> str:
    """Return the current UTC time as an ISO-8601 string with a Z suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class AccountStore:
    """Manages encrypted SQLCipher database for accounts."""

    def __init__(self, path: str | Path = VAULT_DB_FILE) -> None:
        self.path = Path(path)
        self.conn: sqlite3.Connection | None = None

    @classmethod
    def default(cls) -> "AccountStore":
        return cls(default_db_path())

    @property
    def salt_path(self) -> Path:
        return self.path.with_name(VAULT_SALT_FILE)

    def exists(self) -> bool:
        return self.path.is_file()

    def is_open(self) -> bool:
        return self.conn is not None

    def open(self, master_key: bytes) -> None:
        """Open or initialize the encrypted SQLCipher database using master_key."""
        if not isinstance(master_key, (bytes, bytearray)):
            raise TypeError("master_key must be bytes.")

        self.close()

        if self.path.parent and str(self.path.parent) != ".":
            self.path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(str(self.path))
        try:
            cursor = conn.cursor()
            _apply_key(cursor, master_key)
            cursor.execute("PRAGMA temp_store = MEMORY;")
            cursor.execute("PRAGMA secure_delete = ON;")
            # Reading the schema is what actually proves the key is right:
            # PRAGMA key itself never fails.
            cursor.execute("SELECT count(*) FROM sqlite_master;")
            _create_schema(cursor)
            _migrate_schema(cursor)
            conn.commit()
        except (sqlite3.DatabaseError, MemoryError) as error:
            conn.close()
            raise ValueError("Master Password errata") from error
        except Exception:
            conn.close()
            raise

        self.conn = conn
        _restrict_to_current_user(self.path)

    def _cursor(self) -> sqlite3.Cursor:
        if self.conn is None:
            raise AccountStoreError("Database is not open.")
        return self.conn.cursor()

    def set_account_username(self, username: str) -> None:
        """Store the account username in the encrypted metadata table."""
        if not isinstance(username, str):
            raise TypeError("username must be a string.")

        cursor = self._cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('username', ?);",
            (username,),
        )
        self.conn.commit()

    def get_account_username(self) -> str | None:
        """Retrieve the account username from the encrypted metadata table."""
        cursor = self._cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = 'username';")
        row = cursor.fetchone()
        return str(row[0]) if row else None

    def add_account(self, service: str, username: str, password: str) -> int:
        """Insert account credentials into the encrypted vault, returning the new id."""
        _require_credential_fields(service, username, password)

        now = utc_now_text()
        cursor = self._cursor()
        cursor.execute(
            """INSERT INTO accounts (service, username, password, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?);""",
            (service, username, password, now, now),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def update_account(self, account_id: int, service: str, username: str, password: str) -> None:
        """Replace the fields of one credential and refresh its updated_at stamp."""
        _require_credential_fields(service, username, password)

        cursor = self._cursor()
        cursor.execute(
            """UPDATE accounts
               SET service = ?, username = ?, password = ?, updated_at = ?
               WHERE id = ?;""",
            (service, username, password, utc_now_text(), int(account_id)),
        )
        if cursor.rowcount == 0:
            raise AccountStoreError(f"No credential with id {account_id}.")
        self.conn.commit()

    def delete_account(self, account_id: int) -> None:
        """Remove one credential permanently."""
        cursor = self._cursor()
        cursor.execute("DELETE FROM accounts WHERE id = ?;", (int(account_id),))
        if cursor.rowcount == 0:
            raise AccountStoreError(f"No credential with id {account_id}.")
        self.conn.commit()

    def get_account(self, account_id: int) -> tuple[Any, ...] | None:
        """Return one credential row, or None when the id is unknown."""
        cursor = self._cursor()
        cursor.execute(f"SELECT {ACCOUNT_COLUMNS} FROM accounts WHERE id = ?;", (int(account_id),))
        return cursor.fetchone()

    def get_all_accounts(self) -> list[tuple[Any, ...]]:
        """Retrieve all credentials, ordered by service name."""
        cursor = self._cursor()
        cursor.execute(
            f"SELECT {ACCOUNT_COLUMNS} FROM accounts ORDER BY service COLLATE NOCASE, username;"
        )
        return cursor.fetchall()

    def search_accounts(self, query: str) -> list[tuple[Any, ...]]:
        """Search accounts by service name or username/email matching query."""
        if not isinstance(query, str):
            raise TypeError("query must be a string.")

        term = query.strip()
        if not term:
            return self.get_all_accounts()

        pattern = f"%{_escape_like_wildcards(term)}%"
        cursor = self._cursor()
        cursor.execute(
            f"""SELECT {ACCOUNT_COLUMNS} FROM accounts
                WHERE service LIKE ? ESCAPE ? OR username LIKE ? ESCAPE ?
                ORDER BY service COLLATE NOCASE, username;""",
            (pattern, LIKE_ESCAPE_CHARACTER, pattern, LIKE_ESCAPE_CHARACTER),
        )
        return cursor.fetchall()

    def count_accounts(self) -> int:
        cursor = self._cursor()
        cursor.execute("SELECT count(*) FROM accounts;")
        return int(cursor.fetchone()[0])

    def change_master_key(self, new_key: bytes) -> None:
        """Re-encrypt the whole database under a new key.

        The Argon2id salt is unchanged: a new master password derives a new key
        from the same salt, so vault.salt stays valid and must still be kept.
        """
        if not isinstance(new_key, (bytes, bytearray)):
            raise TypeError("new_key must be bytes.")
        if self.conn is None:
            raise AccountStoreError("Database is not open.")

        self.conn.execute(f"PRAGMA rekey = \"x'{bytes(new_key).hex()}'\";")
        self.conn.commit()

    def backup_to(self, destination_dir: str | Path) -> Path:
        """Write a consistent copy of the vault and its salt into a new folder.

        Both files are needed to unlock a vault, so backing up only the database
        would produce something that can never be opened again.
        """
        if self.conn is None:
            raise AccountStoreError("Database is not open.")

        destination = Path(destination_dir) / f"luxcipher-backup-{_timestamp_slug()}"
        destination.mkdir(parents=True, exist_ok=False)

        db_copy = destination / VAULT_DB_FILE
        # VACUUM INTO writes a consistent snapshot without closing the vault,
        # and keeps it encrypted under the current key.
        self.conn.execute("VACUUM INTO ?;", (str(db_copy),))

        if self.salt_path.is_file():
            shutil.copy2(self.salt_path, destination / VAULT_SALT_FILE)

        _restrict_to_current_user(db_copy)
        return destination

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


def _apply_key(cursor: sqlite3.Cursor, key: bytes) -> None:
    cursor.execute(f"PRAGMA key = \"x'{bytes(key).hex()}'\";")


def _create_schema(cursor: sqlite3.Cursor) -> None:
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
            password TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        );"""
    )


def _migrate_schema(cursor: sqlite3.Cursor) -> None:
    """Bring an older vault up to the current schema, in place.

    Version 1 vaults have no timestamp columns. They are added rather than
    rebuilt, so no credential is ever copied through a temporary table.
    """
    cursor.execute("PRAGMA table_info(accounts);")
    columns = {row[1] for row in cursor.fetchall()}

    for column in ("created_at", "updated_at"):
        if column not in columns:
            cursor.execute(
                f"ALTER TABLE accounts ADD COLUMN {column} TEXT NOT NULL DEFAULT '';"
            )

    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?);",
        (str(SCHEMA_VERSION),),
    )


def _require_credential_fields(service: str, username: str, password: str) -> None:
    for name, value in (("service", service), ("username", username), ("password", password)):
        if not isinstance(value, str):
            raise TypeError("service, username, and password must be strings.")

    if not service.strip():
        raise ValueError("service cannot be empty.")
    if not password:
        raise ValueError("password cannot be empty.")


def _escape_like_wildcards(term: str) -> str:
    """Escape LIKE metacharacters so a search for "%" matches a literal percent sign."""
    escaped = term.replace(LIKE_ESCAPE_CHARACTER, LIKE_ESCAPE_CHARACTER * 2)
    escaped = escaped.replace("%", LIKE_ESCAPE_CHARACTER + "%")
    return escaped.replace("_", LIKE_ESCAPE_CHARACTER + "_")


def _timestamp_slug() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _restrict_to_current_user(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
