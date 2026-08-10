"""Local JSON storage for LuxCipher account metadata."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from luxcipher.auth import LocalAccount


ACCOUNT_FILE_NAME = "account.json"
APP_DIR_NAME = "LuxCipher"
ENV_HOME = "LUXCIPHER_HOME"


class AccountStoreError(RuntimeError):
    """Raised when local account metadata cannot be read or written."""


@dataclass(frozen=True)
class AccountStore:
    path: Path

    @classmethod
    def default(cls) -> "AccountStore":
        return cls(default_account_path())

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> LocalAccount:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("account file must contain a JSON object.")
            return LocalAccount.from_dict(data)
        except FileNotFoundError as error:
            raise AccountStoreError("Local account does not exist.") from error
        except (JSONDecodeError, KeyError, TypeError, ValueError, OSError) as error:
            raise AccountStoreError("Local account metadata is invalid.") from error

    def save(self, account: LocalAccount, *, overwrite: bool = False) -> None:
        if not isinstance(account, LocalAccount):
            raise TypeError("account must be a LocalAccount object.")

        if self.exists() and not overwrite:
            raise AccountStoreError("Local account already exists.")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = _to_json(account.to_dict())
        temporary_path = self.path.with_name(f"{self.path.name}.tmp")

        try:
            temporary_path.write_text(payload, encoding="utf-8")
            _restrict_to_current_user(temporary_path)
            temporary_path.replace(self.path)
            _restrict_to_current_user(self.path)
        except OSError as error:
            raise AccountStoreError("Could not save local account metadata.") from error


def default_account_path() -> Path:
    configured_home = os.environ.get(ENV_HOME)
    if configured_home:
        return Path(configured_home).expanduser() / ACCOUNT_FILE_NAME

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / APP_DIR_NAME / ACCOUNT_FILE_NAME

    return Path.home() / f".{APP_DIR_NAME.lower()}" / ACCOUNT_FILE_NAME


def _to_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _restrict_to_current_user(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass
