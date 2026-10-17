# Security and privacy model

TraceGuard is an educational integrity monitor, not an antivirus, access-control
mechanism, privileged security agent, or forensic chain of custody.

## Local trust boundary

The monitored root is selected explicitly. The tool reads file bytes to compute hashes
but stores only hashes, relative paths, and metadata. It never executes, quarantines,
rewrites, deletes, or uploads monitored files. Console output, the database, and report
exports can expose names and fingerprints; treat them as private local artifacts.

Runtime defaults have no outbound network connections. The local server binds to
`127.0.0.1`; the CLI rejects public bindings. Assets and documentation are bundled.
Audit API endpoints are read-only. Folder selection requires a custom request header
and a matching browser Origin, preventing cross-site forms from changing the location.
The API has no CORS permissions, rejects non-loopback Host headers, and
sets no-store, anti-framing, and content security headers. Local processes and local
users can still access the API; there is no authentication. Do not port-forward it.
Optional email is an explicit user-selected exception and sends counts/scores only.

## Tamper evidence

The database and configuration are covered by an HMAC using a separate 32-byte random
key. All legitimate transactions verify the previous seal and generate a new one.
SQLite checks also inspect structural consistency. Mismatches block normal operations
and appear as CLI errors or API HTTP 409. Suspect storage is preserved for review.

An integrity failure is not written into the suspect database automatically because
doing so would legitimize altered history. Explicit `integrity --acknowledge` accepts
the inspected state and appends a critical tampering incident. It is an audit trail of
the acknowledgment, not a reconstruction of what an external editor changed. Back up
the suspect state before acknowledgment if you need to preserve evidence.

Keep state private using OS permissions; POSIX key creation requests mode 0600.
Windows `chmod` is not an ACL boundary, so protect the directory through Windows ACLs.
An administrator or the same compromised user can read the key, forge a seal, replace
all state, disable monitoring, modify the application, or interfere with file reads.
Restoring an older coherent database/config/key/seal also evades this local checkpoint.
Strong rollback resistance would require independently protected trusted storage.

There is a deliberate crash window between SQLite commit and checkpoint replacement.
Interruption can raise the same alarm as tampering. Inspect before acknowledging.
For backups, stop `watch` and `serve`, verify integrity, then copy the entire state
directory to trusted local storage. Restore coherent sets, not isolated database files.

## Filesystem and platform limits

Symlinks, Windows junctions/reparse points, special files, and directory metadata are
skipped. Stat checks and no-follow opens where supported reduce link races, but a tree
walk is not an atomic snapshot and does not eliminate adversarial path replacement.
Changes occurring and reverting between scans may be missed. Reconciliation recovers
persistent differences when Watchdog drops notifications.

Permission modes, UID/GID where available, size, and modification time are tracked.
Windows ACLs, alternate data streams, extended attributes, Linux capabilities, and
access timestamps are not audited. Hashes cover the normal file data stream only.
Unreadable or continuously changing files abort the entire scan. The watcher reports
the error and retries at its next reconciliation rather than fabricating deletions.

Use synthetic, non-sensitive directories when learning. Automated tests and demo
scripts use only temporary data and never select real sensitive directories.
