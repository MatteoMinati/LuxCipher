"""Secure password generation utilities."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


AMBIGUOUS_CHARACTERS = set("0OIl1")
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 12
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


@dataclass(frozen=True)
class PasswordOptions:
    length: int = 20
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.length, int) or isinstance(self.length, bool):
            raise TypeError("length must be an integer.")

        for field_name in (
            "use_lowercase",
            "use_uppercase",
            "use_digits",
            "use_symbols",
            "exclude_ambiguous",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a boolean.")


def generate_password(options: PasswordOptions) -> str:
    """Generate a password with at least one character from each enabled set."""
    pools = _enabled_pools(options)

    if options.length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Length must be at least {MIN_PASSWORD_LENGTH} characters.")

    if options.length > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Length cannot be greater than {MAX_PASSWORD_LENGTH} characters.")

    if not pools:
        raise ValueError("Select at least one character set.")

    if options.length < len(pools):
        raise ValueError("Length is too short for the selected character sets.")

    password_chars = [secrets.choice(pool) for pool in pools]
    all_characters = "".join(pools)

    remaining_length = options.length - len(password_chars)
    password_chars.extend(secrets.choice(all_characters) for _ in range(remaining_length))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def _enabled_pools(options: PasswordOptions) -> list[str]:
    candidates = [
        (options.use_lowercase, string.ascii_lowercase),
        (options.use_uppercase, string.ascii_uppercase),
        (options.use_digits, string.digits),
        (options.use_symbols, SYMBOLS),
    ]

    pools = []
    for enabled, characters in candidates:
        if not enabled:
            continue

        if options.exclude_ambiguous:
            characters = "".join(
                character for character in characters if character not in AMBIGUOUS_CHARACTERS
            )

        if characters:
            pools.append(characters)

    return pools


def evaluate_password_strength(password: str) -> tuple[float, str, str]:
    """Calculate password strength score (0.0 to 1.0), description label, and color hex."""
    if not password:
        return (0.0, "Nessuna", "#71717A")

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in SYMBOLS for c in password)

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])

    if length < 12:
        return (0.25, "Molto Debole", "#EF4444")
    elif length < 16:
        if variety_count >= 3:
            return (0.50, "Media", "#F59E0B")
        return (0.35, "Debole", "#EF4444")
    elif length < 22:
        if variety_count >= 3:
            return (0.80, "Forte", "#06B6D4")
        return (0.60, "Media", "#F59E0B")
    else:  # length >= 22
        if variety_count >= 3:
            return (1.0, "Molto Forte", "#10B981")
        return (0.85, "Forte", "#06B6D4")

