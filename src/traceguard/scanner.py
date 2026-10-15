"""Fail closed on incomplete scans; never follow filesystem links."""

import fnmatch
import os
import stat
from pathlib import Path

from traceguard.hashing import file_record
from traceguard.models import FileRecord, Settings


class ScanError(RuntimeError):
    pass


def is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def excluded(path: Path, root: Path, state: Path, patterns: list[str]) -> bool:
    if path == state or state in path.parents:
        return True
    relative = path.relative_to(root).as_posix()
    return any(
        fnmatch.fnmatchcase(relative, pattern)
        or any(fnmatch.fnmatchcase(part, pattern) for part in path.relative_to(root).parts)
        for pattern in patterns
    )


def snapshot(settings: Settings, state: Path) -> dict[str, FileRecord]:
    root = Path(settings.root)
    if not root.is_dir() or is_link(root):
        raise ScanError(f"Monitoring root is missing or is a symlink: {root}")
    found: dict[str, FileRecord] = {}

    def walk(directory: Path) -> None:
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if excluded(path, root, state, settings.excludes):
                    continue
                if is_link(path):
                    continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    walk(path)
                elif stat.S_ISREG(info.st_mode):
                    relative = path.relative_to(root).as_posix()
                    found[relative] = file_record(path, relative)

    try:
        walk(root)
    except OSError as exc:
        raise ScanError(f"Incomplete scan; previous state preserved: {exc}") from exc
    return found
