from pathlib import Path

import pytest

from traceguard.baseline import scan
from traceguard.detection import differences
from traceguard.models import Event, FileRecord
from traceguard.reporting import report_data
from traceguard.severity import score_event, severity


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("script.ps1", "Script"),
        ("app.exe", "Executable"),
        (".ssh/authorized_keys", "SSH-related"),
        ("Startup/run.txt", "Startup"),
        ("www/index.html", "Web directory"),
    ],
)
def test_rules(path: str, reason: str) -> None:
    event = score_event(Event(kind="created", path=path))
    assert event.score > 10
    assert any(reason in r for r in event.reasons)


def test_rename_scores_both_paths() -> None:
    event = score_event(Event(kind="renamed", path="safe.txt", old_path=".ssh/authorized_keys"))
    assert event.severity == "high"


def test_critical_tampering() -> None:
    event = score_event(Event(kind="database_tampering", path="traceguard.db"), True)
    assert event.score == 100
    assert event.severity == "critical"


@pytest.mark.parametrize(
    ("score", "label"), [(0, "low"), (25, "medium"), (50, "high"), (80, "critical")]
)
def test_thresholds(score: int, label: str) -> None:
    assert severity(score) == label


def test_mass_changes_across_scans_and_grouping(project: tuple[Path, Path]) -> None:
    root, state = project
    for i in range(4):
        (root / f"file{i}.txt").write_text(str(i))
        scan(state)
    data = report_data(state)
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["event_count"] == 4
    assert all(any("Mass changes" in r for r in e["reasons"]) for e in data["events"])
    assert all(e["score"] >= 50 for e in data["events"])


def test_ambiguous_rename_is_create_delete() -> None:
    def record(path):
        return FileRecord(
            path=path,
            sha256="a" * 64,
            size=1,
            mtime_ns=0,
            mode=0o644,
            uid=0,
            gid=0,
            device=0,
            inode=0,
        )

    before = {path: record(path) for path in ("a", "b")}
    after = {path: record(path) for path in ("c", "d")}
    assert sorted(e.kind for e in differences(before, after)) == [
        "created",
        "created",
        "deleted",
        "deleted",
    ]


@pytest.mark.parametrize("kind", ["deleted", "metadata"])
def test_removing_executable_permissions_retains_executable_risk(kind: str) -> None:
    before = FileRecord(
        path="tool",
        sha256="a" * 64,
        size=1,
        mtime_ns=0,
        mode=0o755,
        uid=0,
        gid=0,
        device=0,
        inode=1,
    )
    after = before.model_copy(update={"mode": 0o644}) if kind == "metadata" else None
    event = score_event(Event(kind=kind, path="tool", before=before, after=after))
    assert "Executable: +25" in event.reasons
