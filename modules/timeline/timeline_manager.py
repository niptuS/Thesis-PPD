"""
Timeline Manager — datetime-aware event scheduling.
Events have offset_s (seconds from execution start) and can compute
absolute datetimes relative to a base time.
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional


def _parse_datetime(s: str) -> Optional[datetime]:
    """Parse 'DD/MM/YYYY HH:MM:SS' or 'HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS'."""
    for fmt in ("%d/%m/%Y %H:%M:%S", "%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _format_datetime(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S")


def _format_time(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S")


def _offset_str(seconds: int) -> str:
    m, s = divmod(abs(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


@dataclass
class TimelineEvent:  # pylint: disable=no-member
    event_id: str = ""
    offset_s: int = 0          # seconds from execution start
    event_type: str = "benign"   # benign | attack
    action: str = ""
    source: str = ""
    target: str = ""
    duration_s: int = 0
    label: str = ""
    notes: str = ""
    status: str = "queued"   # queued | running | completed | skipped | expired
    scheduled_dt: str = ""         # absolute datetime "DD/MM/YYYY HH:MM:SS" (display only)

    def __post_init__(self):
        if not self.event_id:
            self.event_id = uuid.uuid4().hex[:8]
        if not self.label:
            self.label = self.action or f"{self.event_type}_{self.event_id}"

    def offset_str(self) -> str:
        return _offset_str(self.offset_s)

    def compute_absolute_dt(self, base: datetime) -> datetime:
        return base + timedelta(seconds=self.offset_s)

    def update_scheduled_dt(self, base: datetime) -> None:
        self.scheduled_dt = _format_datetime(self.compute_absolute_dt(base))

    def is_expired(self, base: datetime) -> bool:
        return self.compute_absolute_dt(base) < datetime.now()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TimelineEvent":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class TimelineManager:
    def __init__(self):
        self._events: list[TimelineEvent] = []

    @property
    def events(self) -> list[TimelineEvent]:
        return list(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def get(self, index: int) -> Optional[TimelineEvent]:
        if 0 <= index < len(self._events):
            return self._events[index]
        return None

    def add(self, event: TimelineEvent) -> None:
        self._events.append(event)
        self._sort()

    def remove(self, index: int) -> bool:
        if 0 <= index < len(self._events):
            self._events.pop(index)
            return True
        return False

    def clear(self):
        self._events.clear()

    def _sort(self):
        self._events.sort(key=lambda e: e.offset_s)

    def find_index(self, event_id: str) -> int:
        for i, ev in enumerate(self._events):
            if ev.event_id == event_id:
                return i
        return -1

    def to_list(self) -> list[dict]:
        return [ev.to_dict() for ev in self._events]

    def load_from_list(self, data: list[dict]) -> None:
        self._events = [TimelineEvent.from_dict(d) for d in data]
        self._sort()

    # ── datetime-aware operations ───────────────────────────────

    def get_base_time(self, scenario_start: str) -> datetime:
        """
        Determine the base time for execution:
        - If scenario start is in the future → use it
        - If scenario start is in the past → use now()
        """
        parsed = _parse_datetime(scenario_start)
        now = datetime.now()
        if parsed and parsed > now:
            return parsed
        return now

    def update_all_scheduled(self, base: datetime) -> None:
        """Recalculate all absolute datetimes from a base time."""
        for ev in self._events:
            ev.update_scheduled_dt(base)

    def get_pending_events(self) -> list[TimelineEvent]:
        """Get events that haven't been executed yet."""
        return [ev for ev in self._events if ev.status in ("queued", "expired")]

    def get_completed_events(self) -> list[TimelineEvent]:
        return [ev for ev in self._events if ev.status == "completed"]

    def mark_expired(self, base: datetime) -> int:
        """Mark events whose scheduled time has already passed."""
        count = 0
        for ev in self._events:
            if ev.status == "queued" and ev.is_expired(base):
                ev.status = "expired"
                count += 1
        return count

    def reset_pending(self) -> None:
        """Reset expired events back to queued for re-execution."""
        for ev in self._events:
            if ev.status in ("expired", "skipped"):
                ev.status = "queued"

    def recalculate_for_resume(self, new_base: datetime) -> None:
        """
        When resuming after abort: keep original offsets but
        update scheduled_dt from new base time. Reset pending events.
        """
        self.reset_pending()
        self.update_all_scheduled(new_base)

    def get_default_datetime(self, scenario_start: str) -> str:
        """
        Default datetime for new events:
        - If scenario start is future → scenario start
        - If past → current time
        """
        base = self.get_base_time(scenario_start)
        return _format_datetime(base)

    def get_default_offset(self) -> int:
        """Suggest next offset: 5 minutes after the last event."""
        if self._events:
            return self._events[-1].offset_s + 300
        return 300  # 5 min default
