# Architecture

`cli.py` exposes Typer commands with Rich output and actionable error messages.
`config.py` resolves local state paths; `models.py` uses Pydantic to validate settings,
file observations, and events. There are no network clients in the scanner or storage.

## Data flow

1. `scanner.snapshot` walks the selected root without following links and streams
   regular files through `hashing.file_record`. Hashing compares identity, size,
   timestamps, and modes before/after reading, with three attempts for unstable files.
2. `detection.differences` compares the new observation with the last successful scan.
   Unique filesystem identities identify renames; unique hash/size pairs provide a
   fallback. Metadata changes carry full before/after records.
3. `database.add_events` groups incidents by time, computes explainable severity, and
   escalates recent events if a mass-change threshold is crossed across several scans.
4. The observed snapshot advances inside the same transaction as the event history.
   The trusted snapshot changes only during initialization or explicit approval.
5. `watcher.WatchService` debounces relevant Watchdog notifications, rescans periodically,
   and joins the observer during shutdown. Notifications run after storage commits.
6. `reporting.report_data` compares baseline with last observed state and exports audit
   data. The dashboard uses this same read path; it never scans or approves files.

## Storage

`.traceguard/` contains `config.json`, `traceguard.db`, `integrity.key`, `integrity.seal`,
and `state.lock`. Paths are local, not synchronized or uploaded. Exclude this directory
from version control even if using a custom state location.

| Table | Purpose |
| --- | --- |
| snapshots | Baseline and observed file records, keyed by kind and relative path |
| events | Timestamped JSON before/after audit records with incident references |
| incidents | First/last seen, maximum event score, and change count |
| approvals | Timestamp, reviewer note, and trusted file count |

Every database client first takes the cross-process file lock, then an exclusive SQLite
transaction lock. Integrity is verified before application queries, and the new seal is
written after commit while retaining SQLite's exclusive lock. Connections are always
closed. Failed scans roll back instead of advancing state. SQLite uses its standard
rollback journal, not WAL; runtime files must stay together. All SQL values use bound
parameters. Configuration is sealed and cannot be silently edited.

`integrity.py` uses `msvcrt` byte-range locks on Windows and `fcntl` locks on POSIX.
The state-lock wait is bounded at 30 seconds. This supports running `watch` and `serve`
in separate processes against the same local state. Network filesystems and hostile
concurrent direct file writers are outside the supported security boundary.

## API

Run `traceguard serve`; browse `/docs` for offline API documentation and `/openapi.json`
for the schema. No CDN resources, remote fonts, analytics, write endpoints, or CORS
allowances are configured. Host headers are limited to loopback names.

| GET endpoint | Result |
| --- | --- |
| `/` | Dashboard, refreshed every five seconds |
| `/api/status` | Counts, verified integrity, most recent approval |
| `/api/events?limit=100&offset=0` | Newest events, limit 1–1000 |
| `/api/incidents` | Grouped incidents, newest first |
| `/api/drift` | Last observed differences from approved baseline |
| `/api/integrity` | Verified integrity or HTTP 409 |
| `/api/report/json` | Full JSON audit report |
| `/api/report/markdown` | Escaped Markdown audit report |
| `/api/report/html` | Standalone HTML audit report |

The dashboard displays untrusted filenames using DOM `textContent`. HTML reports
escape all data and Markdown reports neutralize active HTML/link/image syntax. Reports
never include file contents. API history currently loads into memory before pagination;
database-side pagination is a future scaling improvement.
