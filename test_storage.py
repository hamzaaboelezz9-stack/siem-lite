"""Verify history integrity, private permissions and single-writer concurrency."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from siem_lite import Alert, AlertStore, Severity, StorageError
from tests.helpers import BASE


def alert() -> Alert:
    """Return valid, minimal evidence for persistence tests."""
    return Alert(
        "brute_force",
        Severity.HIGH,
        "Synthetic repeated failed logins.",
        "192.0.2.1",
        "alice",
        BASE,
        BASE,
        {"failed_logins_at_least": 5, "window_seconds": 60},
    )


class StorageTests(unittest.TestCase):
    """A failed append must preserve prior history and never continue silently."""

    def test_atomic_append_valid_array_and_private_permissions(self) -> None:
        """Separate appends retain both alerts as one valid JSON array."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            with AlertStore(path) as store:
                store.append((alert(),))
                store.append((alert(),))
                self.assertEqual(len(store.history()), 2)
            self.assertEqual(len(json.loads(path.read_text(encoding="utf-8"))), 2)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_second_writer_blocked_but_reader_allowed(self) -> None:
        """Atomic readers may inspect current alerts while the only writer owns its lock."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            with AlertStore(path) as writer:
                writer.append((alert(),))
                with self.assertRaises(StorageError):
                    AlertStore(path)
                with AlertStore(path, read_only=True) as reader:
                    self.assertEqual(len(reader.history()), 1)
                    with self.assertRaises(StorageError):
                        reader.append((alert(),))
            with AlertStore(path) as reopened:
                self.assertEqual(len(reopened.history()), 1)

    def test_failed_replace_preserves_existing_history(self) -> None:
        """An OS failure before publication must leave the prior alert array unchanged."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            with AlertStore(path) as store:
                store.append((alert(),))
                original = path.read_bytes()
                with (
                    patch("siem_lite.os.replace", side_effect=OSError("simulated failure")),
                    self.assertRaises(StorageError),
                ):
                    store.append((alert(),))
                self.assertEqual(path.read_bytes(), original)
                self.assertFalse(list(Path(directory).glob(".siem-alerts-*")))

    def test_corrupt_history_is_not_overwritten(self) -> None:
        """A broken JSON file is refused without replacing the evidence already there."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            path.write_bytes(b"{broken")
            with self.assertRaises(StorageError):
                AlertStore(path)
            self.assertEqual(path.read_bytes(), b"{broken")

    def test_invalid_record_schema_is_refused(self) -> None:
        """Required evidence and event bounds must be checked before dashboard rendering."""
        for field, value in (
            ("evidence", None),
            ("status", "unknown"),
            ("first_event_at", "not-a-date"),
            ("rule_id", "unknown"),
            ("description", "bad\x1btext"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "alerts.json"
                item = alert().to_dict()
                item[field] = value
                path.write_text(json.dumps([item]), encoding="utf-8")
                with self.assertRaises(StorageError):
                    AlertStore(path)

    @unittest.skipIf(
        os.name == "nt", "Symlink creation on Windows can require additional privileges"
    )
    def test_symlink_output_is_refused(self) -> None:
        """Alert publication cannot redirect through a local symlink."""
        with tempfile.TemporaryDirectory() as directory:
            actual = Path(directory) / "actual.json"
            actual.write_text("[]", encoding="utf-8")
            link = Path(directory) / "alerts.json"
            link.symlink_to(actual)
            with self.assertRaises(StorageError):
                AlertStore(link)
            self.assertEqual(actual.read_text(encoding="utf-8"), "[]")


if __name__ == "__main__":
    unittest.main()
