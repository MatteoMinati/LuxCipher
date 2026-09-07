import unittest

from luxcipher.autotype import (
    MIN_MATCHABLE_SERVICE_LENGTH,
    match_credential,
    normalize_window_title,
)


def row(account_id, service, username="user", password="pw", updated_at="2026-01-01T00:00:00Z"):
    return (account_id, service, username, password, "2026-01-01T00:00:00Z", updated_at)


class MatchCredentialTests(unittest.TestCase):
    """The rules that decide where a password may be typed.

    Every case here is a case where getting it wrong means typing a secret into
    the wrong window, so the bias throughout is towards refusing to act.
    """

    def test_matches_a_service_named_in_the_window_title(self) -> None:
        accounts = [row(1, "GitHub"), row(2, "Amazon")]
        match = match_credential("Sign in to GitHub - Google Chrome", accounts)
        self.assertIsNotNone(match)
        self.assertEqual(match[1], "GitHub")

    def test_matching_ignores_case_and_surrounding_text(self) -> None:
        accounts = [row(1, "GitHub")]
        for title in ("github", "  GITHUB login  ", "x github y"):
            with self.subTest(title=title):
                self.assertIsNotNone(match_credential(title, accounts))

    def test_returns_none_when_nothing_matches(self) -> None:
        accounts = [row(1, "GitHub"), row(2, "Amazon")]
        self.assertIsNone(match_credential("Untitled - Notepad", accounts))

    def test_returns_none_for_an_empty_or_missing_title(self) -> None:
        accounts = [row(1, "GitHub")]
        for title in ("", "   ", None):
            with self.subTest(title=title):
                self.assertIsNone(match_credential(title, accounts))

    def test_returns_none_with_no_credentials(self) -> None:
        self.assertIsNone(match_credential("Sign in to GitHub", []))

    def test_very_short_service_names_never_match(self) -> None:
        # A one or two letter service appears inside almost any title, so it
        # would fire on windows that have nothing to do with it.
        short = "a" * (MIN_MATCHABLE_SERVICE_LENGTH - 1)
        accounts = [row(1, short)]
        self.assertIsNone(match_credential(f"an {short} window", accounts))

        exact = "a" * MIN_MATCHABLE_SERVICE_LENGTH
        self.assertIsNotNone(match_credential(f"an {exact} window", [row(1, exact)]))

    def test_the_most_specific_service_wins(self) -> None:
        accounts = [row(1, "GitHub"), row(2, "GitHub Enterprise")]
        match = match_credential("GitHub Enterprise - login", accounts)
        self.assertEqual(match[1], "GitHub Enterprise")

    def test_ties_are_broken_by_most_recently_updated(self) -> None:
        # Two accounts on the same service: either is a plausible answer and
        # neither leaks the password anywhere it does not belong.
        accounts = [
            row(1, "GitHub", username="old", updated_at="2026-01-01T00:00:00Z"),
            row(2, "GitHub", username="new", updated_at="2026-06-01T00:00:00Z"),
        ]
        self.assertEqual(match_credential("GitHub", accounts)[2], "new")
        self.assertEqual(match_credential("GitHub", list(reversed(accounts)))[2], "new")

    def test_rows_without_timestamps_are_accepted(self) -> None:
        # Credentials migrated from a schema v1 vault have empty stamps.
        legacy = (1, "GitHub", "user", "pw", "", "")
        self.assertIsNotNone(match_credential("GitHub", [legacy]))

    def test_blank_service_names_are_ignored(self) -> None:
        self.assertIsNone(match_credential("anything at all", [row(1, "   ")]))

    def test_normalize_window_title(self) -> None:
        self.assertEqual(normalize_window_title("  GitHub  "), "github")
        self.assertEqual(normalize_window_title(None), "")


if __name__ == "__main__":
    unittest.main()
