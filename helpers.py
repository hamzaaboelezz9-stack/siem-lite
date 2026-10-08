"""Canonical synthetic event helpers shared by the tests."""

from datetime import datetime, timedelta, timezone

from siem_lite import Event

BASE = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)


def record(seconds: int = 0, **fields: object) -> dict[str, object]:
    """Build one schema-valid login failure, with explicit caller overrides."""
    result: dict[str, object] = {
        "timestamp": (BASE + timedelta(seconds=seconds)).isoformat(),
        "source_ip": "192.0.2.1",
        "event_type": "login",
        "user": "alice",
        "status": "failure",
    }
    result.update(fields)
    return result


def event(seconds: int = 0, **fields: object) -> Event:
    """Validate a synthetic mapping through the same boundary used by the CLI."""
    return Event.from_mapping(record(seconds, **fields))
