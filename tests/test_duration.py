"""Tests for duration parsing (supports days, weeks, months)."""
import unittest


class TestParseDuration(unittest.TestCase):
    def _parse(self, val):
        from modules.live_executions.live_execution import LiveExecutionEngine
        return LiveExecutionEngine._parse_duration(val)

    def test_hms(self):
        self.assertEqual(self._parse("01:30:00"), 5400)
        self.assertEqual(self._parse("00:05:30"), 330)

    def test_ddhms(self):
        self.assertEqual(self._parse("01:00:00:00"), 86400)
        self.assertEqual(self._parse("07:12:00:00"), 7 * 86400 + 12 * 3600)

    def test_suffix_seconds(self):
        self.assertEqual(self._parse("30s"), 30)

    def test_suffix_minutes(self):
        self.assertEqual(self._parse("5m"), 300)

    def test_suffix_hours(self):
        self.assertEqual(self._parse("2h"), 7200)

    def test_suffix_days(self):
        self.assertEqual(self._parse("7d"), 604800)

    def test_suffix_weeks(self):
        self.assertEqual(self._parse("2w"), 1209600)

    def test_suffix_months(self):
        self.assertEqual(self._parse("1M"), 2592000)

    def test_numeric(self):
        self.assertEqual(self._parse(3600), 3600.0)
        self.assertEqual(self._parse("3600"), 3600.0)

    def test_invalid(self):
        self.assertEqual(self._parse("invalid"), 0.0)
        self.assertEqual(self._parse(""), 0.0)


if __name__ == "__main__":
    unittest.main()
