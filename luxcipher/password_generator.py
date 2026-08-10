"""Secure password generation utilities."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


AMBIGUOUS_CHARACTERS = set("0OIl1")
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


def generate_password(options: PasswordOptions) -> str:
    """Generate a password with at least one character from each enabled set."""
    pools = _enabled_pools(options)

    if options.length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Length must be at least {MIN_PASSWORD_LENGTH} characters.")

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
