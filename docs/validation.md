# Validation record

Validated on 2026-10-18:

- Clean virtual environment and editable installation: successful; `pip check` passes.
- pytest: 88 passed, 1 skipped (Windows symlink permission), 1 dependency warning.
- Ruff lint and format checks: passed.
- mypy: passed for all 18 application modules.
- Temporary-data demo: passed; JSON, Markdown, and HTML generated.
- Installed-CLI lifecycle and real loopback dashboard: passed; server stopped cleanly.
- Dashboard JavaScript: syntax and DOM-stub checks passed using Node, covering data
  loading, stale-data recovery, monitor health, error classification, and folder reset.

Validation is performed with the repository's `.venv`, using Python 3.14 on Windows.
The declared minimum is Python 3.11. Windows-specific creation-time behavior is covered
by a regression test that allows path-stat and descriptor-stat ctime semantics to differ
while preserving stability checks within each source.

Reproduce from the repository root:

```text
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m mypy
.venv\Scripts\python.exe scripts/demo.py
.venv\Scripts\python.exe scripts/validate_local.py
```

The test suite covers hash correctness and unstable reads; create/modify/rename/delete
events; metadata and permission changes; explicit approval and retained history;
ambiguous renames; scoring and mass changes across scans; incomplete scans; exclusions;
state isolation; concurrent scans; integrity tampering, missing state, and recovery;
API Host restrictions and read-only behavior; report escaping; CLI workflows; real
Watchdog delivery and periodic reconciliation; and notification opt-in/privacy.
Regression coverage also includes repeated monitor startup, cleanup after observer
failure, transient scan retries, stopping on integrity failures, finite timing settings,
independent notification delivery, executable deletion scoring, consistent dashboard
snapshots, and JSON errors when local state is busy, invalid, or unreadable.

The symlink-creation test skips if Windows lacks developer-mode/admin permission.
Actual desktop notifications and external SMTP delivery are optional, environment-
dependent integrations; automated tests do not contact an SMTP server. Dependency
versions can produce a Starlette warning about its compatibility HTTPX test client;
this does not affect the application server or test assertions.

The harmless demo and installed-CLI validation use temporary data, export JSON,
Markdown, and HTML, and remove their synthetic monitoring data. The HTTP validation
starts Uvicorn on a real free loopback port and stops/joins its worker in `finally`.
No persistent monitoring processes are left running.
