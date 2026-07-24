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


"""
Entrada: s (str)
Salida: Optional[datetime]
Descripción: Parse 'DD/MM/YYYY HH:MM:SS' or 'HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS'.
"""
def _parse_datetime(s: str) -> Optional[datetime]:
    for fmt in ("%d/%m/%Y %H:%M:%S", "%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


"""
Entrada: dt (datetime)
Salida: str
Descripción: Formats a datetime as 'DD/MM/YYYY HH:MM:SS'.
"""
def _format_datetime(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M:%S")


"""
Entrada: dt (datetime)
Salida: str
Descripción: Formats a datetime as 'HH:MM:SS'.
"""
def _format_time(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S")


"""
Entrada: seconds (int)
Salida: str
Descripción: Formats a number of seconds as an 'HH:MM:SS' offset string.
"""
def _offset_str(seconds: int) -> str:
    m, s = divmod(abs(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


@dataclass
class TimelineEvent:  # pylint: disable=no-member
    event_id: str = ""
    offset_s: int = 0
    event_type: str = "benign"
    action: str = ""
    source: str = ""
    target: str = ""
    duration_s: int = 0
    label: str = ""
    notes: str = ""
    status: str = "queued"
    scheduled_dt: str = ""

    """
    Entrada: None
    Salida: None
    Descripción: Generates an event_id and default label if not provided.
    """
    def __post_init__(self):
        if not self.event_id:
            self.event_id = uuid.uuid4().hex[:8]
        if not self.label:
            self.label = self.action or f"{self.event_type}_{self.event_id}"

    """
    Entrada: None
    Salida: str
    Descripción: Returns the offset formatted as an 'HH:MM:SS' string.
    """
    def offset_str(self) -> str:
        return _offset_str(self.offset_s)

    """
    Entrada: base (datetime)
    Salida: datetime
    Descripción: Computes the absolute datetime for this event given a base time.
    """
    def compute_absolute_dt(self, base: datetime) -> datetime:
        return base + timedelta(seconds=self.offset_s)

    """
    Entrada: base (datetime)
    Salida: None
    Descripción: Updates the scheduled_dt field from the base time.
    """
    def update_scheduled_dt(self, base: datetime) -> None:
        self.scheduled_dt = _format_datetime(self.compute_absolute_dt(base))

    """
    Entrada: base (datetime)
    Salida: bool
    Descripción: Returns True if the event's scheduled time has passed.
    """
    def is_expired(self, base: datetime) -> bool:
        return self.compute_absolute_dt(base) < datetime.now()

    """
    Entrada: None
    Salida: dict
    Descripción: Converts the event to a dictionary.
    """
    def to_dict(self) -> dict:
        return asdict(self)

    """
    Entrada: d (dict)
    Salida: TimelineEvent
    Descripción: Builds a TimelineEvent from a dictionary, ignoring unknown keys.
    """
    @classmethod
    def from_dict(cls, d: dict) -> "TimelineEvent":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class TimelineManager:
    """
    Entrada: None
    Salida: None
    Descripción: Initializes the timeline manager with an empty event list.
    """
    def __init__(self):
        self._events: list[TimelineEvent] = []

    """
    Entrada: None
    Salida: list[TimelineEvent]
    Descripción: Returns a copy of the event list.
    """
    @property
    def events(self) -> list[TimelineEvent]:
        return list(self._events)

    """
    Entrada: None
    Salida: int
    Descripción: Returns the number of events.
    """
    def __len__(self) -> int:
        return len(self._events)

    """
    Entrada: index (int)
    Salida: Optional[TimelineEvent]
    Descripción: Returns the event at the given index, or None if out of range.
    """
    def get(self, index: int) -> Optional[TimelineEvent]:
        if 0 <= index < len(self._events):
            return self._events[index]
        return None

    """
    Entrada: event (TimelineEvent)
    Salida: None
    Descripción: Appends an event and re-sorts by offset.
    """
    def add(self, event: TimelineEvent) -> None:
        self._events.append(event)
        self._sort()

    """
    Entrada: index (int)
    Salida: bool
    Descripción: Removes the event at the given index; returns True if removed.
    """
    def remove(self, index: int) -> bool:
        if 0 <= index < len(self._events):
            self._events.pop(index)
            return True
        return False

    """
    Entrada: None
    Salida: None
    Descripción: Removes all events.
    """
    def clear(self):
        self._events.clear()

    """
    Entrada: None
    Salida: None
    Descripción: Sorts the events by offset_s ascending.
    """
    def _sort(self):
        self._events.sort(key=lambda e: e.offset_s)

    """
    Entrada: event_id (str)
    Salida: int
    Descripción: Returns the index of the event with the given id, or -1.
    """
    def find_index(self, event_id: str) -> int:
        for i, ev in enumerate(self._events):
            if ev.event_id == event_id:
                return i
        return -1

    """
    Entrada: None
    Salida: list[dict]
    Descripción: Serializes all events to a list of dictionaries.
    """
    def to_list(self) -> list[dict]:
        return [ev.to_dict() for ev in self._events]

    """
    Entrada: data (list[dict])
    Salida: None
    Descripción: Replaces events from a list of dictionaries and re-sorts.
    """
    def load_from_list(self, data: list[dict]) -> None:
        self._events = [TimelineEvent.from_dict(d) for d in data]
        self._sort()


    """
    Entrada: scenario_start (str)
    Salida: datetime
    Descripción: Determine the base time for execution:
                 - If scenario start is in the future → use it
                 - If scenario start is in the past → use now()
    """
    def get_base_time(self, scenario_start: str) -> datetime:
        parsed = _parse_datetime(scenario_start)
        now = datetime.now()
        if parsed and parsed > now:
            return parsed
        return now

    """
    Entrada: base (datetime)
    Salida: None
    Descripción: Recalculate all absolute datetimes from a base time.
    """
    def update_all_scheduled(self, base: datetime) -> None:
        for ev in self._events:
            ev.update_scheduled_dt(base)

    """
    Entrada: None
    Salida: list[TimelineEvent]
    Descripción: Get events that haven't been executed yet.
    """
    def get_pending_events(self) -> list[TimelineEvent]:
        return [ev for ev in self._events if ev.status in ("queued", "expired")]

    """
    Entrada: None
    Salida: list[TimelineEvent]
    Descripción: Returns events whose status is 'completed'.
    """
    def get_completed_events(self) -> list[TimelineEvent]:
        return [ev for ev in self._events if ev.status == "completed"]

    """
    Entrada: base (datetime)
    Salida: int
    Descripción: Mark events whose scheduled time has already passed.
    """
    def mark_expired(self, base: datetime) -> int:
        count = 0
        for ev in self._events:
            if ev.status == "queued" and ev.is_expired(base):
                ev.status = "expired"
                count += 1
        return count

    """
    Entrada: None
    Salida: None
    Descripción: Reset expired events back to queued for re-execution.
    """
    def reset_pending(self) -> None:
        for ev in self._events:
            if ev.status in ("expired", "skipped"):
                ev.status = "queued"

    """
    Entrada: new_base (datetime)
    Salida: None
    Descripción: When resuming after abort: keep original offsets but
                 update scheduled_dt from new base time. Reset pending events.
    """
    def recalculate_for_resume(self, new_base: datetime) -> None:
        self.reset_pending()
        self.update_all_scheduled(new_base)

    """
    Entrada: scenario_start (str)
    Salida: str
    Descripción: Default datetime for new events:
                 - If scenario start is future → scenario start
                 - If past → current time
    """
    def get_default_datetime(self, scenario_start: str) -> str:
        base = self.get_base_time(scenario_start)
        return _format_datetime(base)

    """
    Entrada: None
    Salida: int
    Descripción: Suggest next offset: 5 minutes after the last event.
    """
    def get_default_offset(self) -> int:
        if self._events:
            return self._events[-1].offset_s + 300
        return 300
