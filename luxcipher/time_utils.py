"""Shared UTC datetime helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def require_timezone_aware(field_name: str, value: Any) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime.")

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware.")


def format_datetime(value: datetime) -> str:
    require_timezone_aware("datetime", value)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_datetime(value: str) -> datetime:
    if not isinstance(value, str):
        raise TypeError("datetime must be a string.")

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require_timezone_aware("datetime", parsed)
    return parsed.astimezone(timezone.utc)
