# Feature branches and project history

TraceGuard's implementation is organized into retained local branches. Each branch
was merged into `main` with `--no-ff`, so the graph shows the integration of each
feature group. Branches build on the previous merged milestone.

| Branch | Scope | Implementation commit messages |
| --- | --- | --- |
| `chore/project-foundation` | Packaging, dependency declarations, lint/type-check configuration, validated models, configuration paths, license, and runtime exclusions | `chore: configure Python project tooling and safe runtime defaults` |
| `feature/file-integrity` | Stable streaming hashes, filesystem change detection, severity scoring, trusted baselines, SQLite audit storage, incidents, tamper evidence, reports, and core tests | `feat: add stable file hashing and filesystem change detection`; `feat: persist baselines, incidents and tamper-evident audit reports` |
| `feature/live-monitoring` | Watchdog, debouncing, periodic reconciliation, console/desktop/email notifications, environment examples, and tests | `feat: add Watchdog monitoring and opt-in notifications` |
| `feature/local-dashboard` | Typer CLI, loopback dashboard, read-only FastAPI endpoints, offline API documentation, and API/CLI tests | `feat: add local dashboard, read-only API and CLI` |
| `test/local-validation` | Harmless temporary-data demonstration and installed-CLI/HTTP validation scripts | `test: add harmless demo and end-to-end localhost validation` |
| `docs/project-guides` | Installation, usage, architecture, detection rules, security limits, validation results, and this history guide | `docs: document setup, security model and feature workflow` |

Inspect the history:

```text
git log --all --graph --decorate --oneline
git log --first-parent --oneline main
git branch --merged main
git log --no-merges --oneline main
```

Existing history is preserved. The retained branches show the implementation's
feature milestones and provide starting points for inspecting each group of changes.

Commits and branch creation are local. A remote repository does not receive them until
an explicit push. No push is performed as part of this workflow. Unrelated nested
repositories are excluded from the commits.

For future changes, branch from current `main`, implement and validate one feature,
then integrate it with a merge commit after review:

```text
git switch main
git switch -c feature/your-feature
python -m pytest -q
python -m ruff check .
python -m mypy
git add path/to/changed-file
git diff --cached --check
git diff --cached
git commit -m "feat: describe the completed feature"
git switch main
git merge --no-ff feature/your-feature -m "merge: integrate your feature"
```

Review and commit only intended files. Never stage runtime databases, local integrity
keys, credentials, personal reports, or unrelated nested repositories.
