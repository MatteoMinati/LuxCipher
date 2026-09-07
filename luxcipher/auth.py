"""Master key derivation and credential rules for the local LuxCipher vault."""

from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
from typing import Any

import argon2.low_level


MIN_MASTER_PASSWORD_LENGTH = 12
SALT_BYTES = 16
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

VAULT_SALT_FILE = "vault.salt"
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32


def default_salt_path() -> Path:
    """Return standard user data path for the vault salt file."""
    configured_home = os.environ.get("LUXCIPHER_HOME")
    if configured_home:
        return Path(configured_home).expanduser() / VAULT_SALT_FILE

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "LuxCipher" / VAULT_SALT_FILE

    return Path.home() / ".luxcipher" / VAULT_SALT_FILE


def get_or_create_salt(salt_path: str | Path | None = None) -> bytes:
    """Load an existing 16-byte salt from vault.salt or create and persist a new one."""
    path = Path(salt_path) if salt_path is not None else default_salt_path()
    if path.is_file():
        salt = path.read_bytes()
        if len(salt) != SALT_BYTES:
            # Regenerating here would derive a different master key and leave any
            # existing vault permanently undecryptable, reported only as a wrong
            # master password. Refuse instead and let the user decide.
            raise ValueError(
                f"Salt file {path} is corrupted: expected {SALT_BYTES} bytes, "
                f"found {len(salt)}. The vault cannot be unlocked without the "
                "original salt. Delete this file only if no vault exists yet."
            )
        return salt

    salt = secrets.token_bytes(SALT_BYTES)
    if path.parent and str(path.parent) != ".":
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(salt)
    return salt


def derive_master_key(
    master_password: str,
    salt: bytes | None = None,
    salt_path: str | Path | None = None,
) -> bytes:
    """Derive a 32-byte master key from the master password using Argon2id with OWASP parameters."""
    _require_string("master_password", master_password)
    if salt is None:
        salt = get_or_create_salt(salt_path)

    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes.")

    return argon2.low_level.hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=argon2.low_level.Type.ID,
    )


def normalize_username(username: str) -> str:
    """Return the trimmed username, raising ValueError if it fails USERNAME_PATTERN."""
    _require_string("username", username)
    normalized = username.strip()

    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "username must be 3-64 characters and use only letters, numbers, '.', '_', or '-'."
        )

    return normalized


def is_master_password_strong_enough(master_password: str) -> bool:
    """Return True when the master password meets the minimum strength policy."""
    return (
        isinstance(master_password, str)
        and bool(master_password.strip())
        and len(master_password) >= MIN_MASTER_PASSWORD_LENGTH
    )


def _require_string(field_name: str, value: Any) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")
