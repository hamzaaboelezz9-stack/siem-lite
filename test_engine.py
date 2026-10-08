"""Verify actual detections, threshold boundaries, suppression and policy semantics."""

import unittest
from datetime import time

from siem_lite import CorrelationEngine, Settings, Severity, timestamp
from tests.helpers import event


class EngineTests(unittest.TestCase):
    """Window and policy behavior must be deterministic in event time."""

    def test_brute_force_inclusive_boundary(self) -> None:
        """Exactly five failures over sixty seconds should trigger once."""
        engine = CorrelationEngine(Settings())
        alerts = [
            alert for second in (0, 15, 30, 45, 60) for alert in engine.process(event(second))
        ]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.HIGH)
        self.assertEqual(alerts[0].evidence["failed_logins_at_least"], 5)

    def test_failure_outside_window_does_not_trigger(self) -> None:
        """An expired fifth event cannot contribute to a qualifying window."""
        engine = CorrelationEngine(Settings())
        for second in (0, 15, 30, 45, 61):
            self.assertEqual(engine.process(event(second)), ())

    def test_brute_episode_suppressed_and_rearmed(self) -> None:
        """A continuing episode alerts once; a later fresh episode alerts again."""
        engine = CorrelationEngine(Settings())
        alerts = [
            alert
            for second in (*range(8), *range(100, 105))
            for alert in engine.process(event(second))
        ]
        self.assertEqual(len(alerts), 2)

    def test_independent_ips_do_not_combine(self) -> None:
        """Failures from separate sources are separate correlation groups."""
        engine = CorrelationEngine(Settings())
        for second in range(5):
            self.assertEqual(engine.process(event(second, source_ip=f"192.0.2.{second + 1}")), ())

    def test_mapped_ipv6_shares_ipv4_state(self) -> None:
        """Equivalent address spellings cannot split one attack across groups."""
        engine = CorrelationEngine(Settings())
        alerts = []
        for second in range(5):
            address = "::ffff:192.0.2.1" if second % 2 else "192.0.2.1"
            alerts.extend(engine.process(event(second, source_ip=address)))
        self.assertEqual(len(alerts), 1)

    def test_port_rule_distinct_ports_and_boundary(self) -> None:
        """Five different ports within an inclusive thirty-second window alert."""
        engine = CorrelationEngine(Settings())
        alerts = []
        for second, port in zip((0, 5, 10, 20, 30), (22, 80, 443, 445, 3389)):
            alerts.extend(
                engine.process(
                    event(second, event_type="connection", user="", destination_port=port)
                )
            )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "port_reconnaissance")
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)
        self.assertEqual(alerts[0].evidence["destination_ports"], [22, 80, 443, 445, 3389])

    def test_repeated_port_and_old_ports_do_not_trigger(self) -> None:
        """Repeated ports do not increase cardinality; expired ports are removed."""
        for ports in ((443,) * 6, (22, 80, 443, 445, 3389, 8080)):
            engine = CorrelationEngine(Settings())
            for index, port in enumerate(ports):
                self.assertEqual(
                    engine.process(
                        event(index * 10, event_type="connection", user="", destination_port=port)
                    ),
                    (),
                )

    def test_successes_do_not_count_as_failures(self) -> None:
        """Successful daytime activity cannot trip either failure-count rule."""
        engine = CorrelationEngine(Settings())
        for index in range(10):
            self.assertEqual(engine.process(event(index, status="success")), ())
            self.assertEqual(
                engine.process(
                    event(
                        index,
                        event_type="connection",
                        destination_port=1000 + index,
                        status="success",
                    )
                ),
                (),
            )

    def test_disabled_account_critical(self) -> None:
        """A policy-disabled account succeeding is critical even during working hours."""
        engine = CorrelationEngine(Settings(disabled_users=frozenset({"alice"})))
        alerts = engine.process(event(status="success"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_producer_disabled_flag_and_combined_reasons(self) -> None:
        """Disabled and off-hours conditions combine into one alert with both reasons."""
        engine = CorrelationEngine(Settings())
        alerts = engine.process(event(10 * 3600, status="success", account_disabled=True))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)
        self.assertEqual(len(alerts[0].evidence["reasons"]), 2)

    def test_off_hours_medium_and_weekends(self) -> None:
        """Default off-hours and weekend success events violate the schedule."""
        for at in ("2026-10-05T20:00:00Z", "2026-10-10T10:00:00Z"):
            engine = CorrelationEngine(Settings())
            alert = engine.process(event(timestamp=at, status="success"))[0]
            self.assertEqual(alert.severity, Severity.MEDIUM)

    def test_work_schedule_half_open_and_overnight(self) -> None:
        """Work end is excluded, and overnight shifts belong to their starting day."""
        policy = Settings()
        self.assertTrue(policy.working_time(timestamp("2026-10-05T09:00:00Z")))
        self.assertFalse(policy.working_time(timestamp("2026-10-05T17:00:00Z")))
        overnight = Settings(work_start=time(22), work_end=time(6), workdays=frozenset({4}))
        self.assertTrue(overnight.working_time(timestamp("2026-10-09T22:00:00Z")))
        self.assertTrue(overnight.working_time(timestamp("2026-10-10T05:59:00Z")))
        self.assertFalse(overnight.working_time(timestamp("2026-10-10T06:00:00Z")))
        self.assertFalse(overnight.working_time(timestamp("2026-10-08T23:00:00Z")))

    def test_duplicates_and_late_events_are_visible(self) -> None:
        """Duplicates and out-of-order live events are ignored with separate counters."""
        engine = CorrelationEngine(Settings())
        engine.process(event(10, event_id="event-1"))
        engine.process(event(10, event_id="event-1"))
        engine.process(event(9, event_id="event-2"))
        self.assertEqual(engine.statistics.processed, 1)
        self.assertEqual(engine.statistics.duplicates, 1)
        self.assertEqual(engine.statistics.late_events, 1)

    def test_source_capacity_eviction_is_reported(self) -> None:
        """Bounded memory must expose a lost correlation group instead of hiding it."""
        engine = CorrelationEngine(Settings(max_sources=1, max_event_ids=1))
        engine.process(event(0, event_id="one"))
        engine.process(event(1, source_ip="192.0.2.2", event_id="two"))
        self.assertEqual(len(engine.sources), 1)
        self.assertEqual(len(engine.seen_ids), 1)
        self.assertEqual(engine.statistics.capacity_evictions, 1)


if __name__ == "__main__":
    unittest.main()
