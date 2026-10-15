import hashlib
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from traceguard.baseline import approve, scan
from traceguard.config import load_settings
from traceguard.database import Database
from traceguard.hashing import file_record
from traceguard.reporting import report_data
from traceguard.scanner import ScanError, snapshot


def test_lifecycle_and_explicit_baseline(project: tuple[Path, Path]) -> None:
    root, state = project
    path = root / "new.txt"
    path.write_text("first", encoding="utf-8")
    assert [e.kind for e in scan(state)] == ["created"]
    assert scan(state) == []
    path.write_text("modified", encoding="utf-8")
    assert [e.kind for e in scan(state)] == ["modified"]
    path.rename(root / "renamed.txt")
    changes = scan(state)
    assert [(e.kind, e.old_path, e.path) for e in changes] == [
        ("renamed", "new.txt", "renamed.txt")
    ]
    (root / "renamed.txt").unlink()
    assert [e.kind for e in scan(state)] == ["deleted"]
    assert report_data(state)["drift"] == []
    (root / "original.txt").write_text("unapproved", encoding="utf-8")
    scan(state)
    assert len(report_data(state)["drift"]) == 1
    assert report_data(state)["approvals"][0]["note"] == "Initial trusted baseline"
    approve(state, "Reviewed by test")
    data = report_data(state)
    assert data["drift"] == []
    assert data["approvals"][0]["note"] == "Reviewed by test"
    assert len(data["events"]) == 5


def test_approval_scans_unobserved_changes(project: tuple[Path, Path]) -> None:
    root, state = project
    (root / "script.py").write_text("# benign", encoding="utf-8")
    approve(state, "Reviewed")
    data = report_data(state)
    assert data["events"][0]["kind"] == "created"
    assert data["drift"] == []
    with pytest.raises(ValueError):
        approve(state, " ")


def test_hash_streaming(tmp_path: Path) -> None:
    path = tmp_path / "large.bin"
    content = bytes(range(256)) * 20000
    path.write_bytes(content)
    record = file_record(path, path.name)
    assert record.sha256 == hashlib.sha256(content).hexdigest()
    assert record.size == len(content)


def test_metadata_change(project: tuple[Path, Path]) -> None:
    root, state = project
    path = root / "original.txt"
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
    assert [e.kind for e in scan(state)] == ["metadata"]


def test_permissions(project: tuple[Path, Path]) -> None:
    root, state = project
    path = root / "original.txt"
    try:
        path.chmod(stat.S_IREAD)
        events = scan(state)
        assert events[0].kind == "metadata"
        assert any("Permission" in reason for reason in events[0].reasons)
    finally:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_missing_root_preserves_state(project: tuple[Path, Path]) -> None:
    root, state = project
    root.rename(root.with_name("moved"))
    with pytest.raises(ScanError):
        scan(state)
    data = report_data(state)
    assert data["observed_files"] == 1
    assert data["events"] == []


def test_incomplete_scan_preserves_state(project: tuple[Path, Path], monkeypatch) -> None:
    _, state = project

    def unreadable(*args, **kwargs):
        raise PermissionError("simulated unreadable file")

    monkeypatch.setattr("traceguard.scanner.file_record", unreadable)
    with pytest.raises(ScanError):
        scan(state)
    assert report_data(state)["observed_files"] == 1
    assert report_data(state)["events"] == []


def test_state_and_patterns_excluded(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    state = root / ".traceguard"
    (root / ".git").mkdir()
    (root / ".git" / "ignored").write_text("ignore")
    (root / "ignored.tmp").write_text("ignore")
    (root / "nested").mkdir()
    (root / "nested" / "normal.txt").write_text("observe")
    settings = load_settings_for(root, [".git", "*.tmp"])
    Database(state).initialize(settings, snapshot(settings, state))
    assert set(snapshot(settings, state)) == {"nested/normal.txt"}
    assert scan(state) == []


def load_settings_for(root, patterns):
    from traceguard.models import Settings

    return Settings(root=str(root), excludes=patterns)


def test_symlinks_skipped(project: tuple[Path, Path], tmp_path: Path) -> None:
    root, state = project
    external = tmp_path / "outside.txt"
    external.write_text("must not read")
    try:
        (root / "link").symlink_to(external)
        (root / "loop").symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation requires Windows developer mode or permission")
    assert set(snapshot(load_settings(state), state)) == {"original.txt"}


def test_concurrent_scans_deduplicate(project: tuple[Path, Path]) -> None:
    root, state = project
    (root / "new.txt").write_text("new")
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: scan(state), range(4)))
    assert sum(len(events) for events in results) == 1
    assert len(report_data(state)["events"]) == 1


def test_initialize_refuses_existing_state(project: tuple[Path, Path]) -> None:
    _, state = project
    with pytest.raises(ValueError):
        Database(state).initialize(load_settings(state), {})
    Database(state).check()


def test_unicode_paths_are_relative_and_roundtrip(project: tuple[Path, Path]) -> None:
    root, state = project
    directory = root / "nested"
    directory.mkdir()
    path = directory / "සිංහල λ.txt"
    path.write_text("Unicode contents: λ", encoding="utf-8")
    event = scan(state)[0]
    assert event.path == "nested/සිංහල λ.txt"
    assert report_data(state)["events"][0]["path"] == event.path
