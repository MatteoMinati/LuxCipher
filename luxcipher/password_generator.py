"""Secure password generation utilities."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass


AMBIGUOUS_CHARACTERS = set("0OIl1")
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 12
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
VERY_STRONG_ENTROPY_BITS = 100.0


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


def estimate_entropy_bits(password: str) -> float:
    """Estimate password entropy in bits from its character pool and repetition.

    Pool size alone rates "aaaaaaaaaaaaaaaaaaaaaaaa" as strong, so the length is
    scaled by the ratio of distinct characters: a password that reuses the same
    few characters carries far less uncertainty than its length suggests.
    """
    if not password:
        return 0.0

    pool = 0
    if any(character.islower() for character in password):
        pool += len(string.ascii_lowercase)
    if any(character.isupper() for character in password):
        pool += len(string.ascii_uppercase)
    if any(character.isdigit() for character in password):
        pool += len(string.digits)
    if any(character in SYMBOLS for character in password):
        pool += len(SYMBOLS)

    # Characters outside the known classes still contribute uncertainty.
    known = set(string.ascii_letters + string.digits + SYMBOLS)
    pool += len({character for character in password if character not in known})

    if pool < 2:
        return 0.0

    distinct_ratio = len(set(password)) / len(password)
    effective_length = len(password) * distinct_ratio
    return effective_length * math.log2(pool)


def evaluate_password_strength(password: str) -> tuple[float, str, str]:
    """Return a strength score (0.0 to 1.0), an Italian label, and a colour hex."""
    if not password:
        return (0.0, "Nessuna", "#71717A")

    bits = estimate_entropy_bits(password)
    score = min(1.0, bits / VERY_STRONG_ENTROPY_BITS)

    if bits < 40:
        return (score, "Molto Debole", "#EF4444")
    if bits < 60:
        return (score, "Debole", "#EF4444")
    if bits < 80:
        return (score, "Media", "#F59E0B")
    if bits < VERY_STRONG_ENTROPY_BITS:
        return (score, "Forte", "#06B6D4")
    return (score, "Molto Forte", "#10B981")
