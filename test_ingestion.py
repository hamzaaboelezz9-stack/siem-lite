"""Exercise normalization and complete-record file tailing without network access."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from siem_lite import (
    Event,
    InputError,
    MAX_LINE_BYTES,
    Settings,
    Statistics,
    batch_events,
    follow_lines,
    parse_json,
)
from tests.helpers import record


class IngestionTests(unittest.TestCase):
    """Reject ambiguous records and ensure streamed partial data is handled correctly."""

    def test_invalid_fields_are_rejected(self) -> None:
        """Malformed schema values must never reach correlation state."""
        bad_fields = (
            {"timestamp": "2026-10-05T10:00:00"},
            {"timestamp": "not-a-date"},
            {"timestamp": "1970-01-01T00:00:00+14:00"},
            {"source_ip": "example.com"},
            {"source_ip": "999.1.1.1"},
            {"user": "\x1b[31madmin"},
            {"user": "   "},
            {"user": "\u202eadmin"},
            {"event_type": "unknown"},
            {"status": "pending"},
            {"account_disabled": "false"},
            {"destination_port": True},
            {"destination_port": 65536},
            {"destination_port": "443"},
            {"event_type": "connection", "destination_port": None},
        )
        for fields in bad_fields:
            with self.subTest(fields=fields), self.assertRaises(InputError):
                Event.from_mapping(record(**fields))

    def test_timestamp_offset_normalized_and_raw_fields_discarded(self) -> None:
        """Canonical events retain only needed metadata and use one time coordinate."""
        event = Event.from_mapping(
            record(timestamp="2026-10-05T12:00:00+02:00", raw_message="ignored")
        )
        self.assertEqual(event.timestamp.isoformat(), "2026-10-05T10:00:00+00:00")
        self.assertFalse(hasattr(event, "raw_message"))

    def test_ambiguous_json_and_invalid_utf8_rejected(self) -> None:
        """Duplicate keys, non-finite numbers and excessive depth fail closed."""
        for data in (
            b'{"user":"a","user":"b"}',
            b'{"value": NaN}',
            b"\xff",
            b"[" * 14 + b"0" + b"]" * 14,
        ):
            with self.subTest(data=data), self.assertRaises(InputError):
                parse_json(data)

    def test_batch_sorts_and_counts_rejected_records(self) -> None:
        """Batch order is normalized and a bad record is visible without killing good ones."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text(
                json.dumps([record(20), record(0), record(10, status="invalid")]), encoding="utf-8"
            )
            statistics = Statistics()
            events = batch_events(path, "json", statistics)
            self.assertEqual([event.timestamp.second for event in events], [0, 20])
            self.assertEqual(statistics.records_read, 3)
            self.assertEqual(statistics.rejected, 1)

    def test_jsonl_batch_invalid_line(self) -> None:
        """One malformed JSONL line does not discard the other complete records."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes((json.dumps(record()) + "\nnot-json\n\n").encode())
            statistics = Statistics()
            self.assertEqual(len(batch_events(path, "jsonl", statistics)), 1)
            self.assertEqual(statistics.records_read, 2)
            self.assertEqual(statistics.rejected, 1)

    def test_bad_policy_rejected(self) -> None:
        """Schedules and thresholds are checked before processing data."""
        for fields in (
            {"brute_threshold": 0},
            {"port_seconds": -1},
            {"workdays": frozenset()},
            {"timezone_name": "Not/A_Timezone"},
            {"work_start": "09:00"},
            {"disabled_users": "alice"},
        ):
            with self.subTest(fields=fields), self.assertRaises(InputError):
                Settings(**fields)

    def test_live_partial_line_waits_for_completion(self) -> None:
        """A writer's partial record is not emitted before its newline arrives."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'{"event":')

            def complete(_: float) -> None:
                with path.open("ab") as handle:
                    handle.write(b'"test"}\n')

            stream = follow_lines(path)
            try:
                with patch("siem_lite.time.sleep", side_effect=complete) as waiting:
                    self.assertEqual(next(stream), b'{"event":"test"}\n')
                    self.assertEqual(waiting.call_count, 1)
            finally:
                stream.close()

    def test_oversized_line_counted_once(self) -> None:
        """Discard all fragments of one oversized record, then resume at the next line."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b"x" * (MAX_LINE_BYTES * 2) + b"\n{}\n")
            stream = follow_lines(path)
            try:
                self.assertIsNone(next(stream))
                self.assertEqual(next(stream), b"{}\n")
            finally:
                stream.close()

    def test_rename_rotation_and_copy_truncate(self) -> None:
        """Normal rename rotation and a shorter replacement-in-place reopen the stream."""
        for rename in (True, False):
            if rename and os.name == "nt":
                continue  # Windows producers may be unable to rename an open file.
            with self.subTest(rename=rename), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "events.jsonl"
                path.write_bytes(b'{"old":"long initial line"}\n')
                stream = follow_lines(path)
                try:
                    self.assertEqual(next(stream), b'{"old":"long initial line"}\n')
                    if rename:
                        path.rename(Path(directory) / "previous.jsonl")
                    path.write_bytes(b"{}\n")
                    self.assertEqual(next(stream), b"{}\n")
                finally:
                    stream.close()

    @unittest.skipIf(os.name == "nt", "Renaming an open file depends on Windows sharing flags")
    def test_rotation_discards_abandoned_partial_line(self) -> None:
        """The end of an old partial record cannot be combined with a new file."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'{"partial":')

            def rotate(_: float) -> None:
                path.rename(Path(directory) / "previous.jsonl")
                path.write_bytes(b"{}\n")

            stream = follow_lines(path)
            try:
                with patch("siem_lite.time.sleep", side_effect=rotate):
                    self.assertIsNone(next(stream))
                    self.assertEqual(next(stream), b"{}\n")
            finally:
                stream.close()

    def test_from_end_skips_existing_partial_record(self) -> None:
        """Startup at EOF skips the continuation of an already started record."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'{"existing":')

            def append(_: float) -> None:
                with path.open("ab") as handle:
                    handle.write(b'"ignored"}\n{}\n')

            stream = follow_lines(path, from_end=True)
            try:
                with patch("siem_lite.time.sleep", side_effect=append):
                    self.assertEqual(next(stream), b"{}\n")
            finally:
                stream.close()


if __name__ == "__main__":
    unittest.main()
