"""Generate reproducible, entirely synthetic JSON/JSONL events for SIEM-Lite."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

BASE_TIME = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)  # Monday, within default work hours.
EXPECTED_ALERTS = 4


def mock_events() -> list[dict[str, object]]:
    """Return four positive scenarios and benign controls, using documentation-only IPs."""
    events: list[dict[str, object]] = []

    def add(
        seconds: int, address: str, kind: str, user: str, status: str, port: int | None = None
    ) -> None:
        event: dict[str, object] = {
            "timestamp": (BASE_TIME + timedelta(seconds=seconds)).isoformat(),
            "source_ip": address,
            "event_type": kind,
            "user": user,
            "status": status,
        }
        if port is not None:
            event["destination_port"] = port
        events.append(event)

    add(0, "192.0.2.10", "login", "alice", "success")
    add(1, "192.0.2.11", "connection", "", "success", 443)
    add(2, "2001:db8::7", "login", "alice", "success")

    # Positive: five login failures inside sixty seconds.
    for seconds in (5, 15, 25, 35, 45):
        add(seconds, "198.51.100.10", "login", "alice", "failure")
    # Positive: five distinct failed destination ports inside thirty seconds.
    for index, port in enumerate((22, 80, 443, 445, 3389)):
        add(10 + index * 5, "198.51.100.20", "connection", "", "failure", port)
    add(50, "198.51.100.30", "login", "former_employee", "success")

    # Negative controls: slow failures and repeated attempts at the same port.
    for seconds in (100, 120, 140, 160, 180):
        add(seconds, "198.51.100.50", "login", "alice", "failure")
    for seconds in range(100, 105):
        add(seconds, "198.51.100.60", "connection", "", "failure", 443)
    add(10 * 60 * 60, "198.51.100.40", "login", "alice", "success")

    events.sort(key=lambda event: str(event["timestamp"]))
    for index, event in enumerate(events, start=1):
        event["event_id"] = f"demo-{index:03d}"
    return events


def write_logs(path: Path, format_name: str, force: bool = False) -> int:
    """Write private mock logs; require explicit permission to replace an existing file."""
    events = mock_events()
    if format_name == "json":
        payload = json.dumps(events, indent=2) + "\n"
    elif format_name == "jsonl":
        payload = "".join(json.dumps(event) + "\n" for event in events)
    else:
        raise ValueError("Choose json or jsonl.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("The output must not be a symbolic link.")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if force else os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
    return len(events)


def main(argv: Sequence[str] | None = None) -> int:
    """Expose a dependency-free fixture generator usable from Windows, Linux or macOS."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("mock_logs.json"))
    parser.add_argument("--format", choices=("json", "jsonl"), default="json")
    parser.add_argument("--force", action="store_true", help="Replace an existing mock-log output")
    args = parser.parse_args(argv)
    try:
        count = write_logs(args.output, args.format, args.force)
    except (OSError, ValueError):
        print(
            "Cannot write mock logs; check the path or use --force for an existing output.",
            file=sys.stderr,
        )
        return 1
    print(
        f"Generated {count} synthetic events. Expect {EXPECTED_ALERTS} alerts with disabled_users.json and default policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
