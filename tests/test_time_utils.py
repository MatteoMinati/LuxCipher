from datetime import datetime, timezone
import unittest

from luxcipher.time_utils import format_datetime, parse_datetime


class TimeUtilsTests(unittest.TestCase):
    def test_round_trips_timezone_aware_datetime_as_utc(self) -> None:
        value = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)

        restored = parse_datetime(format_datetime(value))

        self.assertEqual(restored, value)

    def test_rejects_naive_datetime_string(self) -> None:
        with self.assertRaises(ValueError):
            parse_datetime("2026-08-10T12:00:00")


if __name__ == "__main__":
    unittest.main()
