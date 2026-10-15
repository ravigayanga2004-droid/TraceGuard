# TraceGuard

TraceGuard is a local-first file integrity monitor and security auditing tool for
cybersecurity education. It stores SHA-256 fingerprints, metadata, events, incidents,
and explicit baseline approvals in SQLite. It never executes monitored files.
No Docker, cloud account, paid API, telemetry, or external infrastructure is required.

## Install

Requires Python 3.11 or newer. Run these commands from the repository root.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e .
```

Windows Command Prompt activation is `.venv\Scripts\activate`.
If PowerShell blocks activation, use `.\.venv\Scripts\python.exe` and
`.\.venv\Scripts\traceguard.exe` directly; changing execution policy is unnecessary.

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

`requirements.txt` installs the editable project plus development tools. For a runtime-only
installation, `python -m pip install -e .` is sufficient. Package installation needs
access to a package index or an existing local wheel cache; runtime is offline by default.

## Start monitoring

Create a harmless directory (PowerShell):

```powershell
New-Item -ItemType Directory -Force demo-monitored-directory
Set-Content demo-monitored-directory/hello.txt 'Trusted example'
traceguard init ./demo-monitored-directory
traceguard scan
traceguard status
traceguard watch
```

For macOS/Linux, create the directory with `mkdir -p demo-monitored-directory` and the
file with `printf 'Trusted example\n' > demo-monitored-directory/hello.txt`, then use the
same `traceguard` commands. Stop monitoring with Ctrl+C.

In another terminal, activate the same environment and start the dashboard:

```text
traceguard serve
```

Open **http://127.0.0.1:8765**. The read-only dashboard shows baseline drift, recent
changes with scoring explanations, grouped incidents, and report downloads. All assets
and API documentation are local; no CDN is used. `serve` does not start monitoring;
run `watch` in another terminal or run `scan` manually. Use Ctrl+C to stop the server.

## Commands

```text
traceguard --help
traceguard init ./demo-monitored-directory --exclude '*.tmp' --interval 30 --mass-threshold 20
traceguard scan
traceguard watch
traceguard status
traceguard approve --note "Reviewed expected deployment"
traceguard approve --note "Reviewed expected deployment" --yes
traceguard integrity
traceguard report --format json --output reports/audit.json
traceguard report --format markdown --output reports/audit.md
traceguard report --format html --output reports/audit.html
traceguard serve --host 127.0.0.1 --port 8765
```

`init` trusts the current files and refuses to overwrite existing state. Review files
before initializing. `scan` updates observations and records events without approving
them. `approve` rescans, records any new changes, replaces the baseline, and retains the
entire event and approval history. Approval prompts unless `--yes` is supplied.

All commands accept `--state PATH` **after the command name**. State defaults to
`.traceguard` relative to the current working directory, or `TRACEGUARD_STATE` if set.
Use the same state path in every terminal. Separate state directories support separate
monitoring roots. Internal configuration stores the resolved local monitoring path;
file records and events use portable relative paths. Reinitialize into a new state
directory if the monitored root moves to another device or location.

Reports use unique timestamped names under `reports/` when `--output` is omitted.
Existing output files are never overwritten. Keep reports outside the monitored root
to avoid generating events for the reports themselves. Reports contain paths, hashes,
metadata, and audit history; file contents are never stored or reported.

## What is detected

- File creation, content modification, deletion, and inferred rename.
- Permission mode, owner/group where supported, and modification timestamp changes.
- Script and executable changes, SSH-related files, startup paths, and web directories.
- Bursts of changes within a configurable time window, including across multiple scans.
- Local SQLite/configuration tampering, missing integrity files, and interrupted commits.

Each event includes before/after records, score, severity, and additive reasons.
Incidents group changes separated by no more than 60 seconds by default. Rules identify
paths and file types; a high score signals review priority, not proof of malware.
See [detection rules](docs/detection.md) for exact weights and grouping behavior.

Watchdog requests debounced scans, with reconciliation every 30 seconds by default.
All regular files are streamed through SHA-256 on each scan, including files whose
size and timestamps appear unchanged. A partial or unstable scan aborts without
advancing observations or recording false deletions. Monitoring retries scan errors;
integrity failures stop the monitor and require inspection.

TraceGuard excludes its own state, `.git`, `.venv`, and `__pycache__`. Additional
`--exclude` patterns match a relative POSIX path or an individual path component using
case-sensitive Python `fnmatch` rules. Excluded directories are pruned. Symlinks,
Windows junctions/reparse points, special files, and empty directories are skipped.

## Database integrity and recovery

TraceGuard verifies an HMAC-SHA-256 seal over the closed/committed SQLite database and
configuration, using a separate random local key. Application transactions use
cross-process locking and SQLite locking; the checkpoint is replaced atomically.
The API returns HTTP 409 on integrity failures. The CLI exits with an error and
preserves the suspect database rather than automatically trusting it.

After inspecting a mismatch, either restore a coherent trusted backup of the entire
state directory, or explicitly accept the inspected state:

```text
traceguard integrity --acknowledge
```

This prompts before resetting the seal and records a **critical database_tampering**
event. Missing keys, missing databases, or structural corruption require restoring a
trusted backup; acknowledgment cannot repair them. Config changes are also sealed:
editing `config.json` deliberately requires the same explicit acknowledgment. Stop
watch/serve first, edit and review the file, then acknowledge before restarting.

The local key is not an independent root of trust. A user with access to the key can
forge the seal, and replacing an entire earlier coherent state can evade detection.
A crash between SQLite commit and seal replacement can produce a mismatch. See the
[security model](docs/security.md) before relying on this for important data.

## Notifications

Console notifications are local and enabled by default. Optional desktop support:

```text
python -m pip install -e ".[desktop]"
traceguard watch --desktop
```

Desktop delivery depends on the operating system and desktop session. Email is disabled
unless `traceguard watch --email` is explicitly used. Set the SMTP variables described
in [.env.example](.env.example) in your shell; TraceGuard does not auto-load `.env`.
STARTTLS is enabled by default. Email and desktop notifications contain counts and
scores only; email never sends paths, hashes, or file contents. SMTP credentials are
read from the environment and never stored in SQLite. Delivery failures do not stop
event recording. SMTP is the only optional outbound runtime connection.

## Test and demonstrate

```text
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy
python scripts/demo.py
python scripts/validate_local.py
```

Both scripts use temporary synthetic directories and clean them on exit. The demo
creates, modifies, renames, and deletes a harmless comment-only script without running
it, generates three report formats, and approves the final baseline. The validation
script exercises the installed CLI, verifies all four event kinds, generates reports,
starts a real dashboard on a free `127.0.0.1` port, checks HTTP responses, and stops it
cleanly. Tests include a real Watchdog observer and periodic reconciliation.

Tests never monitor home, SSH, system directories, or personal files. A symlink test
skips on Windows when symlink creation privileges are unavailable. See
[validation notes](docs/validation.md) for the results on this workspace.

## Architecture and limitations

Source is under [`src/traceguard`](src/traceguard), tests under [`tests`](tests), and
safe examples under [`scripts`](scripts). [Architecture notes](docs/architecture.md)
describe data flow, transactions, and the API.

This educational tool is best suited to small or medium local directory trees.
Full hashing, whole-database integrity checks, and full-history report loading trade
performance for simple, inspectable behavior. Scans are serialized with dashboard
reads; long scans can delay responses or exceed the 30-second state-lock wait.
There is no retention policy, incident-resolution workflow, scheduler installation,
malware analysis, Windows ACL auditing, or automatic remediation. Changes that are
created and removed entirely between scans may not be recorded; a tree scan is not
an atomic filesystem snapshot. Rename matching is inferential and ambiguous matches
remain create/delete events. Dashboard access has no login and trusts local users;
binding is restricted to loopback. Cross-platform code is provided, but this run was
validated on Windows with Python 3.14; other platforms need CI validation.

Recommended next steps: cross-platform CI, indexed/paginated reporting, configurable
retention and incident resolution, OS-specific ACL inspection, and independently
protected audit checkpoints for stronger tamper resistance.

## Git workflow

Feature branches and their commit groups are described in
[the project history guide](docs/git-workflow.md). View the local progress graph with
`git log --all --graph --decorate --oneline`.

Runtime state, databases, reports, environments, and secrets are ignored. No commits
or pushes are performed automatically. Review files first; to commit manually:

```text
git status --short
git diff -- README.md
git add .gitignore .env.example LICENSE README.md pyproject.toml requirements.txt src tests scripts docs
git diff --cached --check
git diff --cached
git commit -m "feat: build TraceGuard file integrity monitor"
```

Inspect new files in VS Code before staging.
`git diff` does not show untracked files until they are staged.
Only run the final commit command when you choose to commit. Nothing is pushed.
