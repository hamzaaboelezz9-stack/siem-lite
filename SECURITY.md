# Security notes

SIEM-Lite performs passive local analysis. It sends no network requests, executes no input commands, blocks no hosts and modifies no source log or account configuration.

## Trust boundaries

- Treat event records as untrusted: schema, UTF-8, identifiers, ports, numeric IPs, depth and sizes are validated. Raw record contents are not included in error messages. Canonical fields alone reach the engine.
- Treat the operating system, the Python runtime, the collector directory and the disabled-account policy as trusted. Use a dedicated unprivileged account with read permission for normalized logs and write permission for its own alert directory. Administrator privileges are unnecessary.
- Protect producer integrity. The tool cannot independently confirm account status or establish whether a supplied success/failure result is true. It cannot detect changes to logs it never receives, clock forgery, or an attacker disabling the collector.
- Alert metadata includes usernames and IP addresses. Protect `alerts.json`, policy files and original logs with access controls and a retention policy. POSIX creation modes are private; Windows needs appropriate ACLs. Existing input and parent-directory permissions remain the operator's responsibility.
- Use a local filesystem with working advisory locks and atomic same-directory replacement. Network filesystem semantics and an attacker modifying a trusted directory are outside this design's assumptions.

## Design choices

Strict timestamps and a single event-time order make correlation reproducible. A late live record is counted and discarded rather than incorrectly counted in a newer window. In-memory source and ID caches are bounded; source evictions are visible. Duplicate IDs must be globally unique in a stream.

Alerts are atomically published as a JSON array and announced only after persistence succeeds. Invalid existing history is refused; it is never silently replaced. One writer is enforced by an OS lock, while read-only dashboards read atomic snapshots. Symbolic-link outputs and input/output aliases are refused. File `fsync` precedes replacement, but this is not an encrypted, signed or tamper-evident audit store and does not guarantee power-loss recovery.

The engine does not persist correlation windows, deduplication IDs or stream offsets across restarts. It cannot promise exactly-once alert delivery. After stopping the collector, archive rather than deleting history when retention limits are reached.

All detections require investigation. Off-hours events and repeated failures can be legitimate. A Critical disabled-account success means the supplied evidence contradicts policy, not that the tool has confirmed attacker control.

## Reporting a vulnerability

After publishing this project, enable GitHub private vulnerability reporting. Use that private channel when available, or contact the repository maintainer privately through their published contact details. Include affected version, safe reproduction steps and expected versus actual behavior. Use synthetic events and redact personal data; do not attach passwords, tokens or real confidential logs to public issues.

There has been no independent security audit or operating-system certification. Linux regression tests and demo runs are included; platform-specific behavior should be validated before using this as part of an operational monitoring process.
