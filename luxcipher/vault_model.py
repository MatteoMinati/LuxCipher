"""Data model for decrypted LuxCipher vault contents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


VAULT_SCHEMA_VERSION = 1


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_text(field_name: str, value: str) -> str:
    _require_string(field_name, value)

    if not value.strip():
        raise ValueError(f"{field_name} cannot be empty.")

    return value


def _require_string(field_name: str, value: Any) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")


def _require_timezone(field_name: str, value: datetime) -> None:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware.")


def _format_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    _require_string("datetime", value)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass(frozen=True)
class VaultEntry:
    """One password record while the vault is unlocked in memory."""

    id: str
    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)

    @classmethod
    def create(
        cls,
        *,
        title: str,
        password: str,
        username: str = "",
        url: str = "",
        notes: str = "",
    ) -> "VaultEntry":
        now = _utc_now()
        return cls(
            id=str(uuid4()),
            title=_require_text("title", title).strip(),
            username=username,
            password=_require_text("password", password),
            url=url,
            notes=notes,
            created_at=now,
            updated_at=now,
        )

    def __post_init__(self) -> None:
        _require_string("id", self.id)
        UUID(self.id)
        _require_text("title", self.title)
        _require_text("password", self.password)
        _require_string("username", self.username)
        _require_string("url", self.url)
        _require_string("notes", self.notes)
        _require_timezone("created_at", self.created_at)
        _require_timezone("updated_at", self.updated_at)

        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "createdAt": _format_datetime(self.created_at),
            "updatedAt": _format_datetime(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultEntry":
        return cls(
            id=data["id"],
            title=data["title"],
            username=data.get("username", ""),
            password=data["password"],
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            created_at=_parse_datetime(data["createdAt"]),
            updated_at=_parse_datetime(data["updatedAt"]),
        )


@dataclass(frozen=True)
class VaultData:
    """Decrypted vault payload before encryption is added."""

    entries: tuple[VaultEntry, ...] = field(default_factory=tuple)
    schema_version: int = VAULT_SCHEMA_VERSION
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)

    @classmethod
    def empty(cls) -> "VaultData":
        now = _utc_now()
        return cls(created_at=now, updated_at=now)

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        for entry in entries:
            if not isinstance(entry, VaultEntry):
                raise TypeError("entries must contain VaultEntry objects.")

        object.__setattr__(self, "entries", entries)

        if self.schema_version != VAULT_SCHEMA_VERSION:
            raise ValueError(f"Unsupported vault schema version: {self.schema_version}.")

        _require_timezone("created_at", self.created_at)
        _require_timezone("updated_at", self.updated_at)

        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "createdAt": _format_datetime(self.created_at),
            "updatedAt": _format_datetime(self.updated_at),
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultData":
        entries = tuple(VaultEntry.from_dict(entry) for entry in data.get("entries", ()))
        return cls(
            entries=entries,
            schema_version=int(data["schemaVersion"]),
            created_at=_parse_datetime(data["createdAt"]),
            updated_at=_parse_datetime(data["updatedAt"]),
        )
