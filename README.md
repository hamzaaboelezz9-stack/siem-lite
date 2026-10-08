# SIEM-Lite

A local, standard-library Python security event monitor. It reads normalized JSON logs, correlates three detection rules, prints alerts and collection statistics, and retains alerts in a valid `alerts.json` array. No installation, external service or network connection is required.

This is a lightweight detection tool for small environments. Findings are signals for investigation: repeated failures can be legitimate, and an off-hours login does not prove compromise.

## Quick start

Requires **Python 3.10 or newer**. Extract the project and run these commands from the `siem-lite` directory:

```bash
python siem_lite.py scan mock_logs.json --disabled-users disabled_users.json
python siem_lite.py alerts
python -m unittest discover -s tests -v
```

On Windows, `py` can be used instead of `python`. On systems where Python is named `python3`, use `python3`.

The included demo has **25 synthetic events and produces 4 alerts** under the default policy: one brute-force alert, one reconnaissance alert, one disabled-account alert and one off-hours alert. The IPs are reserved documentation addresses. Nothing connects to those IPs.

Regenerate the demo, or create a JSONL version:

```bash
python generate_mock_logs.py --output mock_logs.json --force
python generate_mock_logs.py --output demo.jsonl --format jsonl
python siem_lite.py scan demo.jsonl --format jsonl --disabled-users disabled_users.json --alerts-file demo_alerts.json
```

`--force` allows replacing an existing generator output. Actual captured batch and live output are also included in `examples/`.

Each scan appends its **new** alerts to the selected history. Run against a fresh output file to compare results with the four-alert example. Replaying logs in a new process produces another set of alerts; event-ID deduplication is in memory and lasts only for that process.

## Files and responsibilities

| File | Purpose |
| --- | --- |
| `siem_lite.py` | Validated ingestion, settings, rolling correlation, alert storage and CLI. Classes can also be imported into another Python program. |
| `generate_mock_logs.py` | Reproducible positive scenarios and benign controls, in JSON or JSONL. |
| `disabled_users.json` | Example static disabled-account policy. |
| `mock_logs.json`, `mock_logs.jsonl` | Ready-to-run synthetic inputs. |
| `examples/sample_alerts.json` | Actual persisted output from the included batch demo. |
| `examples/sample_console.txt` | Actual terminal output from that batch demo. |
| `examples/sample_live_console.txt` | Actual terminal output from the live-follow verification. |
| `tests/` | Standard-library tests for detections, ingestion, persistence and CLI behavior. |
| `SECURITY.md` | Local security assumptions, limitations and disclosure guidance. |

The main module separates its responsibilities into `Event`, `Settings`, `CorrelationEngine`, `Alert`, `AlertStore`, `Statistics`, ingestion helpers and the CLI. Keeping these components together makes the tool easy to copy while each remains independently testable.

## Input schema

For `--format json`, use an array of event objects. For `--format jsonl`, write one complete object per line:

```json
{
  "timestamp": "2026-10-05T10:00:00Z",
  "source_ip": "192.0.2.10",
  "event_type": "connection",
  "user": "",
  "status": "failure",
  "destination_port": 443,
  "event_id": "producer-unique-123",
  "account_disabled": false
}
```

| Field | Accepted values |
| --- | --- |
| `timestamp` | ISO 8601 timestamp with `Z` or an explicit offset; normalized to UTC. UTC year must be 1970–9998. |
| `source_ip` | Numeric IPv4 or IPv6; IPv4-mapped IPv6 is merged with its IPv4 equivalent. No DNS lookup occurs. |
| `event_type` | `login` or `connection`. |
| `user` | Nonblank account name for login; may be empty or omitted for connections. Account matching is case sensitive. |
| `status` | `success` or `failure`. |
| `destination_port` | Optional integer from 1–65535; **required for a failed connection**. |
| `event_id` | Optional unique producer ID. Prevents repeated processing while that ID remains in the bounded in-memory cache. |
| `account_disabled` | Optional JSON boolean, default `false`. A static disabled-user list can independently mark an account disabled. |

Identifiers are limited to 256 characters and cannot contain terminal controls, bidi formatting or surrogate characters. Duplicate JSON keys, non-finite JSON numbers, invalid UTF-8 and excessive nesting are rejected. Unknown event fields are discarded and never copied to alerts. Avoid putting passwords, tokens or raw command lines into normalized records.

### System-log integration

Feed normalized records from your Linux or Windows log exporter. The input is **JSON/JSONL**, not raw `auth.log`, syslog text or binary Windows EVTX. Your exporter maps authentication and network outcomes to the schema above, supplies timezone-aware timestamps, and translates disabled-account information into the policy file or `account_disabled` field.

This project deliberately avoids guessing whether a vendor-specific numeric event or an arbitrary log line indicates failure. Producer accuracy and account-policy accuracy are prerequisites for meaningful alerts.

## Detection rules

| Rule ID | Trigger | Default severity |
| --- | --- | --- |
| `brute_force` | At least 5 failed login events from one source IP within 60 seconds. Counts failures across accounts. | High |
| `unauthorized_access` | Successful login for a disabled account, or outside the configured schedule. | Critical when disabled; Medium when only off-hours. |
| `port_reconnaissance` | Failed connections from one source IP to at least 5 **distinct** destination ports within 30 seconds. | Medium |

Window boundaries are inclusive: the first rule counts an event exactly 60 seconds old; the third counts an event exactly 30 seconds old. Successful events do not contribute to either failure-count rule. A successful login does not erase earlier failures.

Threshold rules emit **one alert per continuing qualifying episode**, limiting duplicate alert noise. They rearm once the next relevant event reveals that the rolling count is below threshold, and trigger when a new qualifying count is reached. Disabled-account and off-hours conditions for the same successful login are combined into one alert with both reasons.

Only the latest threshold-sized failure evidence and most recently attempted distinct ports are retained for each source. This is sufficient to answer whether the threshold has been reached; alert evidence reports **at least** the threshold rather than an exact total for a longer episode.

### Working hours and account policy

Defaults are **Monday–Friday, 09:00 inclusive to 17:00 exclusive, UTC**. Weekends are outside that schedule. Set an explicit timezone and schedule for your environment:

```bash
python siem_lite.py scan mock_logs.json --disabled-users disabled_users.json --timezone UTC --work-start 08:30 --work-end 18:00 --workdays mon,tue,wed,thu,fri
```

An overnight schedule such as `--work-start 22:00 --work-end 06:00` belongs to the weekday on which the shift starts. UTC always works without timezone packages. Other IANA timezone names use Python's `zoneinfo` and require an available system timezone database; some Windows installations only support UTC without installing additional timezone data. An unavailable zone produces a clear error.

The disabled-user policy is a JSON array of exact account names:

```json
["former_employee", "deactivated_service_account"]
```

Tune thresholds independently when needed:

```bash
python siem_lite.py scan mock_logs.json --brute-threshold 8 --brute-window 60 --port-threshold 10 --port-window 30
```

## Live collection

Create an empty regular JSONL file and have a trusted producer append newline-terminated records. In another terminal:

```bash
python siem_lite.py scan live.jsonl --format jsonl --follow --disabled-users disabled_users.json
```

Add `--from-end` to skip existing content, including the continuation of any record already partially written. Otherwise existing complete records are read before new records. New alerts are persisted before they are printed. Use this independent read-only view while collection is running:

```bash
python siem_lite.py alerts --limit 20
```

Press **Ctrl+C** to stop collection and print statistics. The writer lock is automatically released. POSIX rename rotation and ordinary copy-truncate rotation are handled; incomplete abandoned records are rejected. Windows producers should append to a stable file because renaming an open file depends on operating-system sharing flags. Rapid copy-truncate followed by regrowth past the old read offset between polls cannot reliably be detected; prefer rename rotation on POSIX.

### Event-time ordering

Batch input is stably sorted by timestamp before correlation. Live input must have nondecreasing timestamps. Older live records are counted as `late_events` and ignored to prevent incorrect window calculations. Equal timestamps are accepted. Producer IDs must be unique across all producers feeding one process.

This collector has no reorder buffer, persisted read offset or durable correlation state. A restart begins new windows and, unless `--from-end` is used, rereads the existing stream. Synchronize producer clocks and understand that lost/late events or forged timestamps can reduce detection coverage.

## Alert persistence and dashboard

`alerts.json` is a JSON **array**, created when the first alert is triggered. Each append loads existing history, adds new alerts, writes a same-directory temporary file, flushes and `fsync`s that file, then atomically replaces the history. This keeps the published JSON valid if a write is interrupted before replacement. It does not provide a database transaction across collector state and storage or a guarantee against every power-loss/filesystem failure.

Only one writer can hold the OS lock for a history at a time. Readers use atomic snapshots and can run concurrently. Output symlinks are rejected, and output cannot alias the input or policy file. On POSIX, newly created alert and lock files have mode `0600`; newly created alert directories have mode `0700`. On Windows, restrict the directory using filesystem ACLs.

Alerts contain an ID, rule ID, severity, description, source/account metadata, event-time bounds, detection time, `status: "open"`, and limited evidence. This is **plaintext metadata**, not encrypted storage. Raw source logs are not retained in the alert file. The CLI shows all stored open alerts and per-severity counts; scan summaries show records read, logs processed, new alerts, stored open alerts and data-quality counters.

All generated alerts are open. There is no incident-management or automatic-resolution workflow. `detected_at` is the collector's current wall-clock time, while `first_event_at` and `last_event_at` refer to input event time.

Default bounds protect a small local collector:

| Resource | Limit |
| --- | --- |
| Batch input | 16 MiB and 100,000 records |
| JSONL record | 64 KiB including newline during follow |
| JSON nesting | 12 levels |
| Correlation sources | 2,000 recent source states |
| Deduplication cache | 10,000 IDs |
| Alert history | 20,000 alerts and 32 MiB |

Source-capacity evictions are counted because they can reduce correlation coverage. When alert history is full, collection stops rather than silently dropping alerts. Stop the collector, archive the history in a restricted directory, and then start a fresh history. Keep the `.lock` file in place; its presence alone does not mean a writer is running. Persistence rewrites the small array on each alert and is unsuitable for high-volume installations.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed without rejected/late events or source-capacity evictions. |
| `1` | Input, policy, path or persistence error; collection stopped. |
| `2` | Recoverable record rejection, ignored late events or capacity evictions; inspect statistics. Argument syntax errors also use argparse's code 2. |
| `130` | User interrupted collection. Already announced alerts were saved. |

## Verification

```bash
python -m unittest discover -s tests -v
```

The included **38 tests** passed on Linux with Python 3.12. They exercise exact window boundaries, source isolation, distinct-port counting, suppression/rearming, disabled and off-hours policy, overnight shifts, duplicate IDs, malformed records, partial writes, rotation, writer exclusion, atomic-write failure and end-to-end CLI output. The actual live-follow demo also persisted four alerts and exited with code 130 after interruption. Windows-specific file-lock behavior is implemented but has not been executed in this environment.

## GitHub description

> A dependency-free Python SIEM for local JSON logs, with rolling brute-force, access-policy and port-reconnaissance detection, persistent structured alerts, a CLI dashboard and reproducible tests.

License: MIT. Publish the complete folder, including the tests and synthetic examples; keep real logs and runtime alert files out of the repository.
