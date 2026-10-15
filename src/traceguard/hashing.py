"""Streaming hashes with stable-file checks and symlink refusal."""

import hashlib
import os
import stat
from pathlib import Path

from traceguard.models import FileRecord


def file_record(path: Path, relative: str) -> FileRecord:
    for _ in range(3):
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"Not a regular file: {relative}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                continue
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
        current = path.lstat()

        def signature(s: os.stat_result) -> tuple[int, int, int, int, int]:
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode)

        # Windows Python versions can expose different ctime semantics through
        # path stat and descriptor stat. Compare ctime only within each source.
        if (
            signature(before) == signature(opened) == signature(after) == signature(current)
            and before.st_ctime_ns == current.st_ctime_ns
            and opened.st_ctime_ns == after.st_ctime_ns
        ):
            return FileRecord(
                path=relative,
                sha256=digest,
                size=after.st_size,
                mtime_ns=after.st_mtime_ns,
                mode=stat.S_IMODE(after.st_mode),
                uid=getattr(after, "st_uid", 0),
                gid=getattr(after, "st_gid", 0),
                device=after.st_dev,
                inode=after.st_ino,
            )
    raise OSError(f"File changed repeatedly while hashing: {relative}")
