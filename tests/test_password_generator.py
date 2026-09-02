import string
import unittest

from luxcipher.password_generator import (
    AMBIGUOUS_CHARACTERS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    SYMBOLS,
    PasswordOptions,
    generate_password,
)


class PasswordGeneratorTests(unittest.TestCase):
    def test_generates_requested_length(self) -> None:
        password = generate_password(PasswordOptions(length=32))

        self.assertEqual(len(password), 32)

    def test_includes_each_enabled_character_set(self) -> None:
        password = generate_password(PasswordOptions(length=20))

        self.assertTrue(any(character in string.ascii_lowercase for character in password))
        self.assertTrue(any(character in string.ascii_uppercase for character in password))
        self.assertTrue(any(character in string.digits for character in password))
        self.assertTrue(any(character in SYMBOLS for character in password))

    def test_can_exclude_ambiguous_characters(self) -> None:
        password = generate_password(
            PasswordOptions(length=64, exclude_ambiguous=True, use_symbols=False)
        )

        self.assertFalse(any(character in AMBIGUOUS_CHARACTERS for character in password))

    def test_requires_at_least_one_character_set(self) -> None:
        options = PasswordOptions(
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )

        with self.assertRaises(ValueError):
            generate_password(options)

    def test_requires_minimum_secure_length(self) -> None:
        options = PasswordOptions(length=MIN_PASSWORD_LENGTH - 1)

        with self.assertRaises(ValueError):
            generate_password(options)

    def test_rejects_too_long_password(self) -> None:
        options = PasswordOptions(length=MAX_PASSWORD_LENGTH + 1)

        with self.assertRaises(ValueError):
            generate_password(options)

    def test_rejects_invalid_option_types(self) -> None:
        with self.assertRaises(TypeError):
            PasswordOptions(length="20")

        with self.assertRaises(TypeError):
            PasswordOptions(use_digits="yes")

    def test_allows_minimum_secure_length(self) -> None:
        options = PasswordOptions(
            length=MIN_PASSWORD_LENGTH,
            use_lowercase=True,
            use_uppercase=True,
            use_digits=True,
            use_symbols=True,
        )

        self.assertEqual(len(generate_password(options)), MIN_PASSWORD_LENGTH)

    def test_evaluate_password_strength(self) -> None:
        from luxcipher.password_generator import evaluate_password_strength

        # Empty password
        score, label, color = evaluate_password_strength("")
        self.assertEqual(score, 0.0)
        self.assertEqual(label, "Nessuna")

        # Short / weak password
        score, label, color = evaluate_password_strength("abc123")
        self.assertLess(score, 0.4)
        self.assertEqual(label, "Molto Debole")

        # Strong password (length >= 22 with variety)
        score, label, color = evaluate_password_strength("V3ry$ecureP@ssw0rd!2026_Lux")
        self.assertEqual(score, 1.0)
        self.assertEqual(label, "Molto Forte")


if __name__ == "__main__":
    unittest.main()

