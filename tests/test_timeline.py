"""Tests for timeline manager with datetime awareness."""
import unittest
from datetime import datetime, timedelta
from modules.timeline.timeline_manager import (
    TimelineManager, TimelineEvent, _parse_datetime,
)


class TestTimelineEvent(unittest.TestCase):
    def test_create_default(self):
        ev = TimelineEvent()
        self.assertTrue(ev.event_id)  # auto-generated
        self.assertEqual(ev.status, "queued")
        self.assertEqual(ev.offset_s, 0)

    def test_offset_str(self):
        ev = TimelineEvent(offset_s=3661)
        self.assertEqual(ev.offset_str(), "01:01:01")

    def test_compute_absolute_dt(self):
        base = datetime(2025, 6, 15, 10, 0, 0)
        ev = TimelineEvent(offset_s=300)
        dt = ev.compute_absolute_dt(base)
        self.assertEqual(dt, datetime(2025, 6, 15, 10, 5, 0))

    def test_update_scheduled_dt(self):
        base = datetime(2025, 1, 1, 12, 0, 0)
        ev = TimelineEvent(offset_s=60)
        ev.update_scheduled_dt(base)
        self.assertIn("12:01:00", ev.scheduled_dt)

    def test_is_expired(self):
        ev = TimelineEvent(offset_s=0)
        past = datetime.now() - timedelta(hours=1)
        self.assertTrue(ev.is_expired(past))
        future = datetime.now() + timedelta(hours=1)
        self.assertFalse(ev.is_expired(future))

    def test_to_dict_from_dict(self):
        ev = TimelineEvent(offset_s=120, event_type="attack", action="syn_flood",
                           target="10.0.0.1", duration_s=30)
        d = ev.to_dict()
        ev2 = TimelineEvent.from_dict(d)
        self.assertEqual(ev2.offset_s, 120)
        self.assertEqual(ev2.action, "syn_flood")
        self.assertEqual(ev2.target, "10.0.0.1")


class TestTimelineManager(unittest.TestCase):
    def setUp(self):
        self.mgr = TimelineManager()

    def test_add_and_sort(self):
        self.mgr.add(TimelineEvent(offset_s=300, action="second"))
        self.mgr.add(TimelineEvent(offset_s=100, action="first"))
        self.assertEqual(self.mgr.events[0].action, "first")
        self.assertEqual(self.mgr.events[1].action, "second")

    def test_remove(self):
        self.mgr.add(TimelineEvent(offset_s=100))
        self.assertTrue(self.mgr.remove(0))
        self.assertEqual(len(self.mgr), 0)

    def test_remove_invalid_index(self):
        self.assertFalse(self.mgr.remove(5))

    def test_get(self):
        ev = TimelineEvent(offset_s=200, action="test")
        self.mgr.add(ev)
        result = self.mgr.get(0)
        self.assertEqual(result.action, "test")

    def test_get_invalid(self):
        self.assertIsNone(self.mgr.get(99))

    def test_find_index(self):
        ev = TimelineEvent(offset_s=100, action="findme")
        self.mgr.add(ev)
        idx = self.mgr.find_index(ev.event_id)
        self.assertEqual(idx, 0)

    def test_find_index_not_found(self):
        self.assertEqual(self.mgr.find_index("nonexistent"), -1)

    def test_to_list_load_from_list(self):
        self.mgr.add(TimelineEvent(offset_s=100, action="a"))
        self.mgr.add(TimelineEvent(offset_s=200, action="b"))
        data = self.mgr.to_list()
        mgr2 = TimelineManager()
        mgr2.load_from_list(data)
        self.assertEqual(len(mgr2), 2)
        self.assertEqual(mgr2.events[0].action, "a")

    def test_get_base_time_future(self):
        future = (datetime.now() + timedelta(hours=1)).strftime("%H:%M:%S")
        base = self.mgr.get_base_time(future)
        self.assertGreater(base, datetime.now() - timedelta(minutes=1))

    def test_get_base_time_past(self):
        past = "01:00:00"
        base = self.mgr.get_base_time(past)
        diff = abs((base - datetime.now()).total_seconds())
        self.assertLess(diff, 5)  # should be ~now

    def test_pending_events(self):
        self.mgr.add(TimelineEvent(offset_s=100, status="completed"))
        self.mgr.add(TimelineEvent(offset_s=200, status="queued"))
        self.mgr.add(TimelineEvent(offset_s=300, status="queued"))
        pending = self.mgr.get_pending_events()
        self.assertEqual(len(pending), 2)

    def test_default_offset(self):
        self.assertEqual(self.mgr.get_default_offset(), 300)
        self.mgr.add(TimelineEvent(offset_s=600))
        self.assertEqual(self.mgr.get_default_offset(), 900)

    def test_reset_pending(self):
        self.mgr.add(TimelineEvent(offset_s=100, status="expired"))
        self.mgr.reset_pending()
        self.assertEqual(self.mgr.events[0].status, "queued")


class TestDatetimeParsing(unittest.TestCase):
    def test_parse_hms(self):
        dt = _parse_datetime("14:30:00")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.hour, 14)

    def test_parse_full(self):
        dt = _parse_datetime("15/06/2025 10:00:00")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2025)

    def test_parse_invalid(self):
        self.assertIsNone(_parse_datetime("not-a-date"))


if __name__ == "__main__":
    unittest.main()
