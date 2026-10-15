import hashlib
import os
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
