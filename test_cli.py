"""End-to-end mock scans and CLI error/interrupt behavior."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

from generate_mock_logs import mock_events, write_logs
from siem_lite import AlertStore, main
from tests.helpers import record
from tests.test_storage import alert

PROJECT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    """The distributable must work through its actual command-line entry point."""

    def run_cli(self, *args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
        """Invoke the real script with an isolated working directory and bounded runtime."""
        return subprocess.run(
            [sys.executable, str(PROJECT / "siem_lite.py"), *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_mock_json_and_jsonl_produce_exactly_four_alerts(self) -> None:
        """Both input formats detect all positive scenarios while ignoring benign controls."""
        for format_name in ("json", "jsonl"):
            with self.subTest(format=format_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                input_path = root / f"mock.{format_name}"
                self.assertEqual(write_logs(input_path, format_name), 25)
                result = self.run_cli(
                    "scan",
                    str(input_path),
                    "--format",
                    format_name,
                    "--disabled-users",
                    str(PROJECT / "disabled_users.json"),
                    cwd=root,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                alerts = json.loads((root / "alerts.json").read_text(encoding="utf-8"))
                self.assertEqual(len(alerts), 4)
                self.assertEqual(
                    [item["rule_id"] for item in alerts].count("unauthorized_access"), 2
                )
                self.assertEqual(
                    {item["severity"] for item in alerts}, {"Critical", "High", "Medium"}
                )
                self.assertIn("Total logs processed: 25", result.stdout)
                self.assertIn("Total alerts triggered: 4", result.stdout)
                listing = self.run_cli("alerts", cwd=root)
                self.assertEqual(listing.returncode, 0, listing.stderr)
                self.assertIn("4 stored alerts | 4 open", listing.stdout)

    def test_same_output_or_hardlink_cannot_overwrite_input(self) -> None:
        """Path aliases must be refused before acquiring an output writer."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "mock.json"
            write_logs(input_path, "json")
            original = input_path.read_bytes()
            same = self.run_cli("scan", str(input_path), "--alerts-file", str(input_path), cwd=root)
            self.assertEqual(same.returncode, 1)
            self.assertEqual(input_path.read_bytes(), original)
            link = root / "alias.json"
            os.link(input_path, link)
            alias = self.run_cli("scan", str(input_path), "--alerts-file", str(link), cwd=root)
            self.assertEqual(alias.returncode, 1)
            self.assertEqual(input_path.read_bytes(), original)

    def test_lock_sidecar_cannot_modify_input(self) -> None:
        """Even an empty live input cannot be initialized as an output lock file."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "chosen.json.lock"
            input_path.write_bytes(b"")
            result = self.run_cli(
                "scan",
                str(input_path),
                "--format",
                "jsonl",
                "--alerts-file",
                str(root / "chosen.json"),
                cwd=root,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(input_path.read_bytes(), b"")

    def test_bad_record_is_counted_with_degraded_exit(self) -> None:
        """Recoverable record failures give an explicit nonzero result and useful statistics."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "invalid.json"
            path.write_text(json.dumps([record(), {"raw_message": "not echoed"}]), encoding="utf-8")
            result = self.run_cli("scan", str(path), cwd=root)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Rejected: 1", result.stdout)
            self.assertNotIn("not echoed", result.stdout + result.stderr)

    def test_live_follow_requires_jsonl(self) -> None:
        """Misconfigured live input fails before touching alert history."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.run_cli("scan", "mock.json", "--follow", cwd=root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("--format jsonl", result.stderr)
            self.assertFalse((root / "alerts.json").exists())

    def test_follow_interrupt_counts_preexisting_and_new_alerts(self) -> None:
        """Ctrl+C reports saved open alerts, including alerts from previous runs."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, logs = root / "alerts.json", root / "live.jsonl"
            logs.write_bytes(b"")
            with AlertStore(path) as store:
                store.append((alert(),))

            def live(*_: object) -> Iterator[bytes]:
                for index in range(5):
                    yield (json.dumps(record(index, event_id=str(index))) + "\n").encode()
                raise KeyboardInterrupt

            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                patch("siem_lite.follow_lines", side_effect=live),
            ):
                status = main(
                    ["scan", str(logs), "--format", "jsonl", "--follow", "--alerts-file", str(path)]
                )
            self.assertEqual(status, 130)
            self.assertIn("Total alerts triggered: 1 | Stored open alerts: 2", output.getvalue())
            self.assertEqual(len(json.loads(path.read_text(encoding="utf-8"))), 2)

    def test_generator_does_not_replace_existing_file_silently(self) -> None:
        """Regenerating demo data requires explicit replacement authorization."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            write_logs(path, "json")
            with self.assertRaises(FileExistsError):
                write_logs(path, "json")
            self.assertEqual(write_logs(path, "json", force=True), len(mock_events()))


if __name__ == "__main__":
    unittest.main()
