"""Local account authentication for LuxCipher."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from luxcipher.time_utils import format_datetime, parse_datetime, require_timezone_aware, utc_now


ACCOUNT_SCHEMA_VERSION = 1
KDF_NAME = "scrypt"
MASTER_PASSWORD_CONTEXT = b"LuxCipher local account verifier v1"
MIN_MASTER_PASSWORD_LENGTH = 12
SCRYPT_DKLEN = 32
SCRYPT_MAX_DKLEN = 64
SCRYPT_MAXMEM = 64 * 1024 * 1024
SCRYPT_MAXMEM_LIMIT = 256 * 1024 * 1024
SCRYPT_MAX_N = 2**16
SCRYPT_MAX_P = 4
SCRYPT_MAX_R = 16
SCRYPT_MIN_N = 2**10
SCRYPT_N = 2**14
SCRYPT_P = 1
SCRYPT_R = 8
SALT_BYTES = 16
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
VERIFIER_BYTES = 32


@dataclass(frozen=True)
class ScryptParameters:
    """Public KDF parameters stored with the local account."""

    salt: str
    name: str = KDF_NAME
    n: int = SCRYPT_N
    r: int = SCRYPT_R
    p: int = SCRYPT_P
    dklen: int = SCRYPT_DKLEN
    maxmem: int = SCRYPT_MAXMEM

    @classmethod
    def create(
        cls,
        *,
        n: int = SCRYPT_N,
        r: int = SCRYPT_R,
        p: int = SCRYPT_P,
        dklen: int = SCRYPT_DKLEN,
        maxmem: int = SCRYPT_MAXMEM,
    ) -> "ScryptParameters":
        return cls(
            salt=_encode_base64(secrets.token_bytes(SALT_BYTES)),
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=maxmem,
        )

    def __post_init__(self) -> None:
        _require_string("name", self.name)

        if self.name != KDF_NAME:
            raise ValueError(f"Unsupported KDF: {self.name}.")

        if len(_decode_base64("salt", self.salt)) < SALT_BYTES:
            raise ValueError(f"salt must be at least {SALT_BYTES} bytes.")

        _require_int("n", self.n)
        _require_int("r", self.r)
        _require_int("p", self.p)
        _require_int("dklen", self.dklen)
        _require_int("maxmem", self.maxmem)

        if self.n < 2 or self.n & (self.n - 1):
            raise ValueError("scrypt n must be a power of two greater than one.")

        if self.n < SCRYPT_MIN_N:
            raise ValueError(f"scrypt n must be at least {SCRYPT_MIN_N}.")

        if self.n > SCRYPT_MAX_N:
            raise ValueError(f"scrypt n cannot be greater than {SCRYPT_MAX_N}.")

        if self.r < 1 or self.p < 1:
            raise ValueError("scrypt r and p must be positive.")

        if self.r > SCRYPT_MAX_R:
            raise ValueError(f"scrypt r cannot be greater than {SCRYPT_MAX_R}.")

        if self.p > SCRYPT_MAX_P:
            raise ValueError(f"scrypt p cannot be greater than {SCRYPT_MAX_P}.")

        if self.dklen < SCRYPT_DKLEN:
            raise ValueError(f"scrypt dklen must be at least {SCRYPT_DKLEN} bytes.")

        if self.dklen > SCRYPT_MAX_DKLEN:
            raise ValueError(f"scrypt dklen cannot be greater than {SCRYPT_MAX_DKLEN} bytes.")

        if self.maxmem < 0:
            raise ValueError("scrypt maxmem cannot be negative.")

        if self.maxmem > SCRYPT_MAXMEM_LIMIT:
            raise ValueError(f"scrypt maxmem cannot be greater than {SCRYPT_MAXMEM_LIMIT}.")

        if self.maxmem < _minimum_scrypt_maxmem(self.n, self.r):
            raise ValueError("scrypt maxmem is too low for n and r.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "salt": self.salt,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "dklen": self.dklen,
            "maxmem": self.maxmem,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScryptParameters":
        return cls(
            name=data["name"],
            salt=data["salt"],
            n=int(data["n"]),
            r=int(data["r"]),
            p=int(data["p"]),
            dklen=int(data["dklen"]),
            maxmem=int(data.get("maxmem", SCRYPT_MAXMEM)),
        )

@dataclass(frozen=True)
class LocalAccount:
    """Local-only account metadata used to verify a master password."""

    id: str
    username: str
    kdf: ScryptParameters
    password_verifier: str
    schema_version: int = ACCOUNT_SCHEMA_VERSION
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    @classmethod
    def create(
        cls,
        *,
        username: str,
        master_password: str,
        kdf: ScryptParameters | None = None,
    ) -> "LocalAccount":
        normalized_username = _normalize_username(username)
        _require_master_password_strength(master_password)

        account_kdf = kdf or ScryptParameters.create()
        now = utc_now()
        return cls(
            id=str(uuid4()),
            username=normalized_username,
            kdf=account_kdf,
            password_verifier=_create_password_verifier(master_password, account_kdf),
            created_at=now,
            updated_at=now,
        )

    def __post_init__(self) -> None:
        _require_string("id", self.id)
        UUID(self.id)

        if self.schema_version != ACCOUNT_SCHEMA_VERSION:
            raise ValueError(f"Unsupported account schema version: {self.schema_version}.")

        object.__setattr__(self, "username", _normalize_username(self.username))

        if not isinstance(self.kdf, ScryptParameters):
            raise TypeError("kdf must be a ScryptParameters object.")

        if len(_decode_base64("password_verifier", self.password_verifier)) != VERIFIER_BYTES:
            raise ValueError(f"password_verifier must be {VERIFIER_BYTES} bytes.")

        require_timezone_aware("created_at", self.created_at)
        require_timezone_aware("updated_at", self.updated_at)

        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at.")

    def verify_master_password(self, candidate_password: str) -> bool:
        _require_string("candidate_password", candidate_password)

        expected = _decode_base64("password_verifier", self.password_verifier)
        actual = _create_password_verifier_bytes(candidate_password, self.kdf)
        return hmac.compare_digest(expected, actual)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "id": self.id,
            "username": self.username,
            "createdAt": format_datetime(self.created_at),
            "updatedAt": format_datetime(self.updated_at),
            "kdf": self.kdf.to_dict(),
            "passwordVerifier": self.password_verifier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LocalAccount":
        return cls(
            schema_version=int(data["schemaVersion"]),
            id=data["id"],
            username=data["username"],
            created_at=parse_datetime(data["createdAt"]),
            updated_at=parse_datetime(data["updatedAt"]),
            kdf=ScryptParameters.from_dict(data["kdf"]),
            password_verifier=data["passwordVerifier"],
        )


def _create_password_verifier(master_password: str, kdf: ScryptParameters) -> str:
    return _encode_base64(_create_password_verifier_bytes(master_password, kdf))


def _create_password_verifier_bytes(master_password: str, kdf: ScryptParameters) -> bytes:
    key = _derive_master_key(master_password, kdf)
    return hmac.new(key, MASTER_PASSWORD_CONTEXT, hashlib.sha256).digest()


def _derive_master_key(master_password: str, kdf: ScryptParameters) -> bytes:
    _require_string("master_password", master_password)
    return hashlib.scrypt(
        master_password.encode("utf-8"),
        salt=_decode_base64("salt", kdf.salt),
        n=kdf.n,
        r=kdf.r,
        p=kdf.p,
        dklen=kdf.dklen,
        maxmem=kdf.maxmem,
    )


def _normalize_username(username: str) -> str:
    _require_string("username", username)
    normalized = username.strip()

    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "username must be 3-64 characters and use only letters, numbers, '.', '_', or '-'."
        )

    return normalized


def _require_master_password_strength(master_password: str) -> None:
    _require_string("master_password", master_password)

    if not master_password.strip():
        raise ValueError("master_password cannot be blank.")

    if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
        raise ValueError(
            f"master_password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters."
        )


def _require_string(field_name: str, value: Any) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")


def _require_int(field_name: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer.")


def _encode_base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_base64(field_name: str, value: str) -> bytes:
    _require_string(field_name, value)
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as error:
        raise ValueError(f"{field_name} must be valid base64.") from error


def _minimum_scrypt_maxmem(n: int, r: int) -> int:
    return 128 * n * r
