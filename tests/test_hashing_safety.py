import hashlib
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from traceguard.hashing import file_record


def test_stat_and_fstat_ctime_can_differ(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "sample.txt"
    path.write_text("stable content")
    original = os.fstat

    def descriptor_stat(fd):
        info = original(fd)
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields["st_ctime_ns"] += 10_000_000
        return SimpleNamespace(**fields)

    monkeypatch.setattr("traceguard.hashing.os.fstat", descriptor_stat)
    assert file_record(path, path.name).sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_continuously_changing_file_is_rejected(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "changing.txt"
    path.write_bytes(b"initial")
    original = hashlib.file_digest

    def changing(stream, algorithm):
        result = original(stream, algorithm)
        path.write_bytes(path.read_bytes() + b"x")
        return result

    monkeypatch.setattr("traceguard.hashing.hashlib.file_digest", changing)
    with pytest.raises(OSError, match="changed repeatedly"):
        file_record(path, path.name)


def test_path_and_descriptor_modes_can_differ(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "playwright.CMD"
    path.write_bytes(b"@echo off\r\nrem harmless fixture\r\n")
    original = os.fstat

    def descriptor_stat(fd):
        info = original(fd)
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        # Reproduce Windows' extension-based executable bits on every platform.
        fields["st_mode"] = path.lstat().st_mode ^ stat.S_IXUSR
        return SimpleNamespace(**fields)

    monkeypatch.setattr("traceguard.hashing.os.fstat", descriptor_stat)
    record = file_record(path, path.name)
    assert record.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record.mode == stat.S_IMODE(path.lstat().st_mode)


@pytest.mark.parametrize("source", ["path", "descriptor"])
def test_permission_changes_during_hashing_are_rejected(
    tmp_path: Path, monkeypatch, source: str
) -> None:
    path = tmp_path / "changing-mode.txt"
    path.write_text("unchanged bytes")
    original = Path.lstat if source == "path" else os.fstat
    calls = 0

    def changing_mode(value):
        nonlocal calls
        info = original(value)
        calls += 1
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        if calls % 2 == 0:
            fields["st_mode"] ^= stat.S_IWUSR
        return SimpleNamespace(**fields)

    if source == "path":
        monkeypatch.setattr(Path, "lstat", changing_mode)
    else:
        monkeypatch.setattr("traceguard.hashing.os.fstat", changing_mode)
    with pytest.raises(OSError, match="changed repeatedly"):
        file_record(path, path.name)


@pytest.mark.parametrize("extension", [".CMD", ".cmd", ".BAT", ".bat", ".EXE", ".exe", ".COM"])
def test_stable_windows_executable_extensions_hash(tmp_path: Path, extension: str) -> None:
    path = tmp_path / f"fixture{extension}"
    content = b"harmless static fixture; never executed\r\n"
    path.write_bytes(content)
    record = file_record(path, path.name)
    assert record.sha256 == hashlib.sha256(content).hexdigest()
    assert record.mode == stat.S_IMODE(path.lstat().st_mode)
