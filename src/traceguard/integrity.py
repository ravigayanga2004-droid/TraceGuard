"""Local tamper evidence and a cross-process state lock.

The key and seal must be protected by the operating system. This is not a defense
against an administrator who can replace the database, key, and seal together.
"""

import hashlib
import hmac
import secrets
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class IntegrityError(RuntimeError):
    pass


@contextmanager
def state_lock(state: Path) -> Iterator[None]:
    state.mkdir(parents=True, exist_ok=True)
    with (state / "state.lock").open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        deadline = time.monotonic() + 30
        while True:
            try:
                stream.seek(0)
                if sys.platform == "win32":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Timed out waiting for another TraceGuard process") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            if sys.platform == "win32":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def digest(state: Path) -> str:
    key = (state / "integrity.key").read_bytes()
    if len(key) != 32:
        raise IntegrityError("Invalid local integrity key")
    result = hmac.new(key, digestmod=hashlib.sha256)
    for name in ("config.json", "traceguard.db"):
        result.update(name.encode())
        with (state / name).open("rb") as stream:
            while block := stream.read(1024 * 1024):
                result.update(block)
    return result.hexdigest()


def seal(state: Path, *, initialize: bool = False) -> None:
    if initialize:
        key = state / "integrity.key"
        with key.open("xb") as stream:
            stream.write(secrets.token_bytes(32))
        key.chmod(0o600)
    temporary = state / "integrity.seal.tmp"
    temporary.write_text(digest(state), encoding="ascii")
    temporary.replace(state / "integrity.seal")


def verify(state: Path) -> None:
    try:
        expected = (state / "integrity.seal").read_text(encoding="ascii")
        if not hmac.compare_digest(expected, digest(state)):
            raise IntegrityError("Database/config tampering or interrupted commit detected")
    except (OSError, UnicodeError) as exc:
        raise IntegrityError(f"Missing or unreadable integrity data: {exc}") from exc
