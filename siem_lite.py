"""SIEM-Lite: local JSON ingestion, event-time correlation and private JSON alerts.

Python 3.10+, standard library only. No network requests or automatic blocking.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import math
import os
import stat
import sys
import tempfile
import time
import unicodedata
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, time as daytime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

UTC = timezone.utc
VERSION = "1.0.0"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_RECORDS = 100_000
MAX_ALERT_BYTES = 32 * 1024 * 1024
MAX_ALERTS = 20_000
MAX_SOURCES = 2_000
MAX_EVENT_IDS = 10_000
MAX_TEXT_LENGTH = 256
MAX_EVIDENCE_BYTES = 8 * 1024
POLL_SECONDS = 0.25
WEEKDAYS = {
    name: index for index, name in enumerate(("mon", "tue", "wed", "thu", "fri", "sat", "sun"))
}
LOG = logging.getLogger("siem_lite")


class InputError(ValueError):
    """A local record or policy cannot be interpreted without ambiguity."""


class StorageError(OSError):
    """Persistence is unavailable; stop instead of silently losing alerts."""


class Severity(str, Enum):
    """Supported alert priorities; rules use context-specific assignments."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


def timestamp(value: object) -> datetime:
    """Require ISO 8601 with an explicit offset and normalize to aware UTC."""
    if not isinstance(value, str) or len(value) > 64:
        raise InputError("Timestamp must be bounded ISO 8601 text.")
    try:
        parsed = datetime.fromisoformat(
            value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else "")
        )
        if parsed.utcoffset() is None:
            raise ValueError("Ambiguous timestamp.")
        normalized = parsed.astimezone(UTC)
        if not 1970 <= normalized.year <= 9998:
            raise ValueError("Timestamp outside supported range.")
        return normalized
    except (ValueError, OverflowError) as error:
        raise InputError("Timestamp must include a valid timezone offset.") from error


def text(value: object, allow_empty: bool = False) -> str:
    """Bound account/identifier text and reject terminal controls and bidi formatting."""
    if (
        not isinstance(value, str)
        or len(value) > MAX_TEXT_LENGTH
        or (not value.strip() and not allow_empty)
    ):
        raise InputError("Text field has an invalid type or length.")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value):
        raise InputError("Text fields cannot contain control or formatting characters.")
    return value


def canonical_ip(value: object) -> str:
    """Use numeric addresses only; merge IPv4-mapped IPv6 with its IPv4 source."""
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise InputError("Source address must be an IPv4 or IPv6 literal.")
    try:
        address = ipaddress.ip_address(value)
        return str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError as error:
        raise InputError("Invalid numeric address.") from error


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON fields are not accepted.")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise InputError("Non-finite JSON numbers are not accepted.")


def parse_json(data: bytes) -> object:
    """Reject duplicate fields, invalid UTF-8, non-finite values and excessive nesting."""
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_nonfinite
        )
        stack = [(value, 0)]
        nodes = 0
        while stack:
            node, depth = stack.pop()
            nodes += 1
            if depth > 12 or nodes > 2_000_000:
                raise InputError("JSON structure exceeds supported bounds.")
            if isinstance(node, dict):
                stack.extend((child, depth + 1) for child in node.values())
            elif isinstance(node, list):
                stack.extend((child, depth + 1) for child in node)
        return value
    except (UnicodeError, ValueError, RecursionError) as error:
        raise InputError("Input is not supported UTF-8 JSON.") from error


@contextmanager
def regular_file(path: Path) -> Iterator[BinaryIO]:
    """Read only regular files; a device or FIFO must not block the collector."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InputError("The input must be a regular local file.")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            yield handle
    finally:
        if descriptor != -1:
            os.close(descriptor)


def bounded_file(path: Path, maximum: int) -> bytes:
    """Bound file allocation before parsing local JSON or configuration."""
    with regular_file(path) as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise InputError("Input file exceeds its configured size limit.")
    return data


@dataclass(frozen=True)
class Event:
    """A normalized event; unknown/raw fields are deliberately not retained."""

    timestamp: datetime
    source_ip: str
    event_type: str
    user: str
    status: str
    destination_port: int | None = None
    event_id: str | None = None
    account_disabled: bool = False

    @classmethod
    def from_mapping(cls, record: object) -> Event:
        """Validate the canonical schema used by mock and normalized system-log producers."""
        if not isinstance(record, dict):
            raise InputError("Each event must be a JSON object.")
        event_type = record.get("event_type")
        status = record.get("status")
        if event_type not in ("login", "connection") or status not in ("success", "failure"):
            raise InputError("Unsupported event type or status.")
        user = text(record.get("user", ""), allow_empty=event_type == "connection")
        port = record.get("destination_port")
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise InputError("Destination port must be an integer from 1 to 65535.")
        if event_type == "connection" and status == "failure" and port is None:
            raise InputError("Failed connection events need a destination port.")
        disabled = record.get("account_disabled", False)
        if type(disabled) is not bool:
            raise InputError("account_disabled must be a JSON boolean.")
        event_id = record.get("event_id")
        return cls(
            timestamp(record.get("timestamp")),
            canonical_ip(record.get("source_ip")),
            event_type,
            user,
            status,
            port,
            text(event_id) if event_id is not None else None,
            disabled,
        )


@dataclass(frozen=True)
class Settings:
    """Thresholds, static account policy, work schedule and bounded correlation capacity."""

    disabled_users: frozenset[str] = frozenset()
    timezone_name: str = "UTC"
    work_start: daytime = daytime(9, 0)
    work_end: daytime = daytime(17, 0)
    workdays: frozenset[int] = frozenset(range(5))
    brute_threshold: int = 5
    brute_seconds: int = 60
    port_threshold: int = 5
    port_seconds: int = 30
    max_sources: int = MAX_SOURCES
    max_event_ids: int = MAX_EVENT_IDS
    zone: timezone | ZoneInfo = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Reject ambiguous schedules and ensure UTC works without an OS timezone database."""
        for name in ("brute_threshold", "port_threshold"):
            value = getattr(self, name)
            if type(value) is not int or not 2 <= value <= 100:
                raise InputError("Rule thresholds must be integers from 2 to 100.")
        for name in ("brute_seconds", "port_seconds"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 3600:
                raise InputError("Rule windows must be integer seconds from 1 to 3600.")
        for name in ("max_sources", "max_event_ids"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 100_000:
                raise InputError("Correlation capacities must be positive bounded integers.")
        if (
            not isinstance(self.workdays, frozenset)
            or not self.workdays
            or any(type(day) is not int or not 0 <= day <= 6 for day in self.workdays)
        ):
            raise InputError("Choose at least one valid working day.")
        if any(not isinstance(value, daytime) for value in (self.work_start, self.work_end)):
            raise InputError("Working-hour bounds must be local time objects.")
        if self.work_start == self.work_end or any(
            value.tzinfo is not None for value in (self.work_start, self.work_end)
        ):
            raise InputError("Working-hour bounds must differ and must be local times.")
        if not isinstance(self.disabled_users, frozenset):
            raise InputError("Disabled users must be a set of exact account names.")
        for user in self.disabled_users:
            text(user)
        text(self.timezone_name)
        try:
            zone = UTC if self.timezone_name == "UTC" else ZoneInfo(self.timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise InputError(
                "Requested timezone is unavailable; use UTC or install system timezone data."
            ) from error
        object.__setattr__(self, "zone", zone)

    def working_time(self, at: datetime) -> bool:
        """Evaluate half-open work hours; overnight shifts belong to their starting weekday."""
        local = at.astimezone(self.zone)
        current = local.time().replace(tzinfo=None)
        day = local.weekday()
        if self.work_start < self.work_end:
            return day in self.workdays and self.work_start <= current < self.work_end
        if current >= self.work_start:
            return day in self.workdays
        return current < self.work_end and (day - 1) % 7 in self.workdays


@dataclass(frozen=True)
class Alert:
    """Minimal structured evidence for one threshold crossing or policy-violating login."""

    rule_id: str
    severity: Severity
    description: str
    source_ip: str
    user: str
    first_event_at: datetime
    last_event_at: datetime
    evidence: dict[str, object]
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, object]:
        """Serialize account/IP metadata without copying original records or secrets."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "description": self.description,
            "status": "open",
            "source_ip": self.source_ip,
            "user": self.user,
            "detected_at": self.detected_at.isoformat(),
            "first_event_at": self.first_event_at.isoformat(),
            "last_event_at": self.last_event_at.isoformat(),
            "evidence": self.evidence,
        }


@dataclass
class Statistics:
    """Visible acceptance, data-quality and bounded-state counters for one collector run."""

    records_read: int = 0
    processed: int = 0
    rejected: int = 0
    duplicates: int = 0
    late_events: int = 0
    alerts_triggered: int = 0
    capacity_evictions: int = 0


@dataclass
class SourceState:
    """Only recent threshold-sized evidence is needed to decide whether a rule is true."""

    failures: deque[datetime]
    ports: OrderedDict[int, datetime] = field(default_factory=OrderedDict)
    last_seen: datetime | None = None
    brute_armed: bool = True
    ports_armed: bool = True


class CorrelationEngine:
    """Apply three rules to nondecreasing event-time input, with bounded source/ID state."""

    def __init__(self, settings: Settings, statistics: Statistics | None = None) -> None:
        """Create per-source rolling state and an optional shared collector counter set."""
        self.settings = settings
        self.statistics = statistics or Statistics()
        self.sources: OrderedDict[str, SourceState] = OrderedDict()
        self.seen_ids: OrderedDict[str, None] = OrderedDict()
        self.watermark: datetime | None = None

    def _source(self, event: Event) -> SourceState:
        lifetime = timedelta(seconds=max(self.settings.brute_seconds, self.settings.port_seconds))
        while self.sources:
            oldest = next(iter(self.sources.values()))
            if oldest.last_seen is None or oldest.last_seen >= event.timestamp - lifetime:
                break
            self.sources.popitem(last=False)
        if event.source_ip not in self.sources:
            if len(self.sources) >= self.settings.max_sources:
                self.sources.popitem(last=False)
                self.statistics.capacity_evictions += 1
            self.sources[event.source_ip] = SourceState(deque(maxlen=self.settings.brute_threshold))
        state = self.sources[event.source_ip]
        state.last_seen = event.timestamp
        self.sources.move_to_end(event.source_ip)
        cutoff = event.timestamp - timedelta(seconds=self.settings.brute_seconds)
        while state.failures and state.failures[0] < cutoff:
            state.failures.popleft()
        cutoff = event.timestamp - timedelta(seconds=self.settings.port_seconds)
        while state.ports and next(iter(state.ports.values())) < cutoff:
            state.ports.popitem(last=False)
        if len(state.failures) < self.settings.brute_threshold:
            state.brute_armed = True
        if len(state.ports) < self.settings.port_threshold:
            state.ports_armed = True
        return state

    def process(self, event: Event) -> tuple[Alert, ...]:
        """Correlate an Event.from_mapping result; count duplicates and late arrivals."""
        if event.event_id is not None and event.event_id in self.seen_ids:
            self.statistics.duplicates += 1
            return ()
        if self.watermark is not None and event.timestamp < self.watermark:
            self.statistics.late_events += 1
            return ()
        self.watermark = event.timestamp
        if event.event_id is not None:
            self.seen_ids[event.event_id] = None
            if len(self.seen_ids) > self.settings.max_event_ids:
                self.seen_ids.popitem(last=False)
        self.statistics.processed += 1
        alerts: list[Alert] = []
        if event.event_type == "login" and event.status == "failure":
            state = self._source(event)
            state.failures.append(event.timestamp)
            if len(state.failures) >= self.settings.brute_threshold and state.brute_armed:
                alerts.append(
                    Alert(
                        "brute_force",
                        Severity.HIGH,
                        "Possible brute force: repeated failed logins from one source.",
                        event.source_ip,
                        event.user,
                        state.failures[0],
                        event.timestamp,
                        {
                            "failed_logins_at_least": self.settings.brute_threshold,
                            "window_seconds": self.settings.brute_seconds,
                        },
                    )
                )
                state.brute_armed = False
        if event.event_type == "connection" and event.status == "failure":
            state = self._source(event)
            assert event.destination_port is not None  # Enforced by canonical event parsing.
            state.ports[event.destination_port] = event.timestamp
            state.ports.move_to_end(event.destination_port)
            if len(state.ports) > self.settings.port_threshold:
                state.ports.popitem(last=False)
            if len(state.ports) >= self.settings.port_threshold and state.ports_armed:
                alerts.append(
                    Alert(
                        "port_reconnaissance",
                        Severity.MEDIUM,
                        "Possible reconnaissance: failures on several distinct destination ports.",
                        event.source_ip,
                        event.user,
                        next(iter(state.ports.values())),
                        event.timestamp,
                        {
                            "unique_ports_at_least": self.settings.port_threshold,
                            "destination_ports": sorted(state.ports),
                            "window_seconds": self.settings.port_seconds,
                        },
                    )
                )
                state.ports_armed = False
        if event.event_type == "login" and event.status == "success":
            reasons: list[str] = []
            disabled = event.account_disabled or event.user in self.settings.disabled_users
            if disabled:
                reasons.append(
                    "Account is marked disabled by the configured policy or event producer."
                )
            if not self.settings.working_time(event.timestamp):
                reasons.append("Login is outside the configured working schedule.")
            if reasons:
                alerts.append(
                    Alert(
                        "unauthorized_access",
                        Severity.CRITICAL if disabled else Severity.MEDIUM,
                        "Successful login violated access policy.",
                        event.source_ip,
                        event.user,
                        event.timestamp,
                        event.timestamp,
                        {
                            "reasons": reasons,
                            "policy_timezone": self.settings.timezone_name,
                            "work_start": self.settings.work_start.isoformat(timespec="minutes"),
                            "work_end": self.settings.work_end.isoformat(timespec="minutes"),
                            "workdays": sorted(self.settings.workdays),
                        },
                    )
                )
        self.statistics.alerts_triggered += len(alerts)
        return tuple(alerts)


class AlertStore:
    """One locked writer logically appends alerts to an atomically replaced JSON array."""

    def __init__(self, path: Path, read_only: bool = False) -> None:
        """Lock writers; readers can inspect atomically published history during collection."""
        self.path = path.absolute()
        self.lock: BinaryIO | None = None
        try:
            if self.path.is_symlink() or any(parent.is_symlink() for parent in self.path.parents):
                raise StorageError("Alert paths must not traverse symbolic links.")
            if read_only:
                self._read()
                return
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            lock_path = Path(str(self.path) + ".lock")
            if lock_path.is_symlink():
                raise StorageError("Lock path must not be a symbolic link.")
            descriptor = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            self.lock = os.fdopen(descriptor, "r+b", buffering=0)
            if not stat.S_ISREG(os.fstat(self.lock.fileno()).st_mode):
                raise StorageError("Lock file must be a regular file.")
            if os.fstat(self.lock.fileno()).st_size == 0:
                self.lock.write(b"0")
            self.lock.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._read()  # Refuse corrupt history before processing any input.
        except (OSError, InputError) as error:
            self.close()
            raise StorageError(
                "Cannot open private alert history or another writer holds its lock."
            ) from error

    def _read(self) -> list[dict[str, object]]:
        if not self.path.exists():
            return []
        if self.path.is_symlink():
            raise StorageError("Alert history must not be a symbolic link.")
        data = parse_json(bounded_file(self.path, MAX_ALERT_BYTES))
        if not isinstance(data, list) or len(data) > MAX_ALERTS:
            raise StorageError("Alert history must be a bounded JSON array.")
        fields = {
            "alert_id",
            "rule_id",
            "severity",
            "description",
            "status",
            "source_ip",
            "user",
            "detected_at",
            "first_event_at",
            "last_event_at",
            "evidence",
        }
        for item in data:
            if (
                not isinstance(item, dict)
                or set(item) != fields
                or item.get("severity") not in tuple(level.value for level in Severity)
            ):
                raise StorageError("Alert history contains an invalid record.")
            for name in ("alert_id", "rule_id", "description", "source_ip", "status"):
                text(item.get(name))
            text(item.get("user"), allow_empty=True)
            canonical_ip(item["source_ip"])
            timestamp(item.get("detected_at"))
            first, last = (
                timestamp(item.get("first_event_at")),
                timestamp(item.get("last_event_at")),
            )
            if first > last or item["status"] not in ("open", "resolved"):
                raise StorageError("Alert history has invalid event bounds or status.")
            if item["rule_id"] not in ("brute_force", "unauthorized_access", "port_reconnaissance"):
                raise StorageError("Alert history has an unsupported rule ID.")
            evidence = item.get("evidence")
            if (
                not isinstance(evidence, dict)
                or len(json.dumps(evidence, ensure_ascii=True).encode()) > MAX_EVIDENCE_BYTES
            ):
                raise StorageError("Alert history has invalid or oversized evidence.")
        return data

    def append(self, alerts: Sequence[Alert]) -> None:
        """Publish a complete JSON array before the CLI announces the new alerts."""
        if not alerts:
            return
        if self.lock is None:
            raise StorageError("Alert writer is closed.")
        temporary: str | None = None
        try:
            history = self._read()
            if len(history) + len(alerts) > MAX_ALERTS:
                raise StorageError("Alert history is full; archive it before continuing.")
            payload = (
                json.dumps(
                    history + [alert.to_dict() for alert in alerts], indent=2, allow_nan=False
                )
                + "\n"
            ).encode()
            if len(payload) > MAX_ALERT_BYTES:
                raise StorageError(
                    "Alert history exceeds its byte budget; archive it before continuing."
                )
            descriptor, temporary = tempfile.mkstemp(prefix=".siem-alerts-", dir=self.path.parent)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except (OSError, InputError) as error:
            raise StorageError("Alert persistence failed; processing was stopped.") from error
        finally:
            if temporary is not None and Path(temporary).exists():
                Path(temporary).unlink()

    def history(self) -> list[dict[str, object]]:
        """Return validated local history for the terminal dashboard."""
        return self._read()

    def close(self) -> None:
        """Release the OS lock without unlinking a file another writer might be using."""
        if self.lock is not None:
            self.lock.close()
            self.lock = None

    def __enter__(self) -> AlertStore:
        """Support an explicit lifetime for the writer lock."""
        return self

    def __exit__(self, kind: object, value: object, traceback: object) -> None:
        """Release resources on normal completion, error or Ctrl+C."""
        self.close()


def batch_events(path: Path, format_name: str, statistics: Statistics) -> list[Event]:
    """Validate a finite JSON array/JSONL file and stably sort by event time."""
    data = bounded_file(path, MAX_INPUT_BYTES)
    if format_name == "json":
        records = parse_json(data)
        if not isinstance(records, list):
            raise InputError("JSON input must be an array of canonical events.")
    else:
        records = [line for line in data.splitlines() if line.strip()]
    if len(records) > MAX_RECORDS:
        raise InputError("Batch contains too many records.")
    events: list[Event] = []
    for record in records:
        statistics.records_read += 1
        try:
            if isinstance(record, bytes):
                if len(record) > MAX_LINE_BYTES:
                    raise InputError("Record exceeds the line limit.")
                record = parse_json(record)
            events.append(Event.from_mapping(record))
        except InputError:
            statistics.rejected += 1
    return sorted(events, key=lambda event: event.timestamp)


def follow_lines(
    path: Path, from_end: bool = False, poll_seconds: float = POLL_SECONDS
) -> Iterator[bytes | None]:
    """Tail bounded complete JSONL lines, handling rename rotation and copy-truncate.

    None represents one malformed oversized or abandoned partial record. Input
    producer timestamps must be nondecreasing; the engine counts late records.
    """
    if not math.isfinite(poll_seconds) or poll_seconds <= 0:
        raise InputError("Polling interval must be positive and finite.")
    first = True
    while True:
        try:
            with regular_file(path) as handle:
                info = os.fstat(handle.fileno())
                identity = (info.st_dev, info.st_ino)
                discarding = False
                if first and from_end:
                    if info.st_size:
                        handle.seek(-1, os.SEEK_END)
                        discarding = handle.read(1) != b"\n"
                    handle.seek(0, os.SEEK_END)
                first = False
                pending = b""
                while True:
                    chunk = handle.readline(MAX_LINE_BYTES + 1)
                    if chunk:
                        if discarding:
                            if chunk.endswith(b"\n"):
                                discarding = False
                            continue
                        if len(pending) + len(chunk) > MAX_LINE_BYTES:
                            pending = b""
                            discarding = not chunk.endswith(b"\n")
                            yield None
                        elif chunk.endswith(b"\n"):
                            line, pending = pending + chunk, b""
                            if line.strip():
                                yield line
                        else:
                            pending += chunk
                        continue
                    try:
                        current = path.stat()
                    except FileNotFoundError:
                        if pending:
                            yield None
                        break
                    if (
                        identity != (current.st_dev, current.st_ino)
                        or current.st_size < handle.tell()
                    ):
                        if pending:
                            yield None
                        break
                    time.sleep(poll_seconds)
        except FileNotFoundError:
            if first:
                raise InputError("Live input must exist at startup.")
            time.sleep(poll_seconds)


def work_time(value: str) -> daytime:
    """Parse unambiguous 24-hour HH:MM CLI input."""
    try:
        if len(value) != 5 or value[2] != ":":
            raise ValueError("Invalid time.")
        return daytime(int(value[:2]), int(value[3:]))
    except ValueError as error:
        raise InputError("Work hours must use HH:MM in 24-hour notation.") from error


def settings_from_args(args: argparse.Namespace) -> Settings:
    """Load an exact static disabled-account list and explicit operator schedule."""
    disabled: frozenset[str] = frozenset()
    if args.disabled_users is not None:
        data = parse_json(bounded_file(args.disabled_users, MAX_LINE_BYTES))
        if not isinstance(data, list):
            raise InputError("Disabled-user policy must be a JSON array of names.")
        disabled = frozenset(text(value) for value in data)
    try:
        workdays = frozenset(WEEKDAYS[value.strip().lower()] for value in args.workdays.split(","))
    except KeyError as error:
        raise InputError("Working days use mon,tue,wed,thu,fri,sat,sun.") from error
    return Settings(
        disabled_users=disabled,
        timezone_name=args.timezone,
        work_start=work_time(args.work_start),
        work_end=work_time(args.work_end),
        workdays=workdays,
        brute_threshold=args.brute_threshold,
        brute_seconds=args.brute_window,
        port_threshold=args.port_threshold,
        port_seconds=args.port_window,
    )


def display_alert(record: dict[str, object]) -> None:
    """Print one persisted alert with safely quoted account text; never print raw log records."""
    account = json.dumps(record["user"], ensure_ascii=True)
    print(f"[{record['severity']}] {record['rule_id']} | {record['source_ip']} | user={account}")
    print(f"  {record['description']}")
    print(f"  evidence={json.dumps(record['evidence'], ensure_ascii=True, sort_keys=True)}")


def dashboard(statistics: Statistics, active: int) -> None:
    """Present accepted events, new alerts and explicit data-quality limitations."""
    print("\nSIEM-Lite | local collection summary")
    print(f"Records read: {statistics.records_read} | Total logs processed: {statistics.processed}")
    print(f"Total alerts triggered: {statistics.alerts_triggered} | Stored open alerts: {active}")
    print(
        f"Rejected: {statistics.rejected} | Duplicates ignored: {statistics.duplicates} | Late events ignored: {statistics.late_events}"
    )
    print(f"Correlation source-capacity evictions: {statistics.capacity_evictions}")


def same_file(left: Path, right: Path) -> bool:
    """Prevent replacing input/policy files, including hard-link aliases."""
    if left.resolve() == right.resolve():
        return True
    try:
        return left.samefile(right)
    except FileNotFoundError:
        return False


def parser() -> argparse.ArgumentParser:
    """Expose batch, live-tail and persisted-alert views with explicit defaults."""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--version", action="version", version=f"SIEM-Lite {VERSION}")
    commands = result.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Process a local JSON array or JSONL event stream")
    scan.add_argument("input", type=Path)
    scan.add_argument("--format", choices=("json", "jsonl"), default="json")
    scan.add_argument("--follow", action="store_true", help="Tail JSONL until Ctrl+C")
    scan.add_argument(
        "--from-end", action="store_true", help="Skip existing bytes when starting live follow"
    )
    scan.add_argument("--alerts-file", type=Path, default=Path("alerts.json"))
    scan.add_argument(
        "--disabled-users", type=Path, help="JSON array of exact disabled account names"
    )
    scan.add_argument("--timezone", default="UTC")
    scan.add_argument("--work-start", default="09:00")
    scan.add_argument("--work-end", default="17:00")
    scan.add_argument("--workdays", default="mon,tue,wed,thu,fri")
    scan.add_argument("--brute-threshold", type=int, default=5)
    scan.add_argument("--brute-window", type=int, default=60, help="Seconds, inclusive boundary")
    scan.add_argument("--port-threshold", type=int, default=5)
    scan.add_argument("--port-window", type=int, default=30, help="Seconds, inclusive boundary")
    listing = commands.add_parser("alerts", help="Display stored open alerts and severity counts")
    listing.add_argument("--alerts-file", type=Path, default=Path("alerts.json"))
    listing.add_argument("--limit", type=int, default=10, help="Most recent alerts to display")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Run one local collector; 0 complete, 2 degraded input, 1 error, 130 interrupted."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    statistics = Statistics()
    active = 0
    try:
        args = parser().parse_args(argv)
        if args.command == "alerts":
            if not 1 <= args.limit <= MAX_ALERTS:
                raise InputError("Alert display limit is outside supported bounds.")
            with AlertStore(args.alerts_file, read_only=True) as store:
                history = store.history()
                active_records = [record for record in history if record["status"] == "open"]
                active = len(active_records)
                print(f"SIEM-Lite | {len(history)} stored alerts | {active} open")
                for severity in Severity:
                    print(
                        f"{severity.value}: {sum(record['severity'] == severity.value for record in active_records)}"
                    )
                for record in active_records[-args.limit :]:
                    display_alert(record)
            return 0
        if args.from_end and not args.follow:
            raise InputError("--from-end requires --follow.")
        if args.follow and args.format != "jsonl":
            raise InputError("Live follow requires --format jsonl.")
        policy = settings_from_args(args)
        outputs = (args.alerts_file, Path(str(args.alerts_file) + ".lock"))
        sources = (args.input, args.disabled_users) if args.disabled_users else (args.input,)
        if any(same_file(output, source) for output in outputs for source in sources):
            raise InputError("Alert output and its lock must differ from input and policy files.")
        engine = CorrelationEngine(policy, statistics)
        with AlertStore(args.alerts_file) as store:
            active = sum(record["status"] == "open" for record in store.history())
            if args.follow:
                print(
                    "SIEM-Lite | following complete JSONL events; press Ctrl+C to stop", flush=True
                )
                for line in follow_lines(args.input, args.from_end):
                    statistics.records_read += 1
                    try:
                        if line is None:
                            raise InputError("Invalid live record.")
                        event = Event.from_mapping(parse_json(line))
                    except InputError:
                        statistics.rejected += 1
                        LOG.warning("Rejected one live record; original content was not logged.")
                        continue
                    alerts = engine.process(event)
                    store.append(alerts)
                    active += len(alerts)
                    for alert in alerts:
                        display_alert(alert.to_dict())
                    sys.stdout.flush()
            else:
                for event in batch_events(args.input, args.format, statistics):
                    alerts = engine.process(event)
                    store.append(alerts)
                    active += len(alerts)
                    for alert in alerts:
                        display_alert(alert.to_dict())
            dashboard(statistics, active)
        return (
            2
            if statistics.rejected or statistics.late_events or statistics.capacity_evictions
            else 0
        )
    except KeyboardInterrupt:
        dashboard(statistics, active)
        LOG.warning("Collector stopped; successfully announced alerts were already persisted.")
        return 130
    except (InputError, StorageError) as error:
        LOG.error("Collector stopped: %s", error)
        return 1
    except OSError:
        LOG.error("Collector stopped: local file access failed; check paths and permissions.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
