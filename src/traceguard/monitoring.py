"""Select local folders without replacing an existing location's audit history."""

import hashlib
import os
import threading
from pathlib import Path
from typing import Any

from traceguard.config import load_settings, selected_state
from traceguard.database import Database
from traceguard.models import Settings
from traceguard.scanner import is_link, snapshot
from traceguard.watcher import WatchService


class Monitoring:
    def __init__(self, state: Path):
        self.base = state.resolve()
        self.lock = threading.RLock()
        self.thread: threading.Thread | None = None
        self.stop = threading.Event()
        self.error: str | None = None

    def active_state(self) -> Path | None:
        if not (self.base / "config.json").exists():
            # Incomplete or damaged state must never be silently reinitialized.
            if self.base.exists() and any(p.name != "state.lock" for p in self.base.iterdir()):
                Database(self.base).check()
            return None
        return selected_state(self.base)

    def directory(self, value: str) -> Path:
        if not value.strip():
            raise ValueError("Enter an absolute folder path")
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError("Use an absolute folder path, such as C:\\Users\\YourName\\Documents")
        if is_link(path):
            raise ValueError("Choose a folder rather than a symlink or junction")
        path = path.resolve(strict=True)
        if not path.is_dir():
            raise ValueError("The selected path must be a folder")
        if path == self.base or self.base in path.parents:
            raise ValueError("Choose a folder outside TraceGuard's state directory")
        return path

    def folders(self, value: str | None) -> dict[str, Any]:
        path = self.directory(value) if value else Path.home()
        directories = []
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    child = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False) and not is_link(child):
                        if child != self.base:
                            directories.append({"name": entry.name, "path": str(child)})
                except OSError:
                    continue
        roots = [str(Path.home())]
        if os.name == "nt":
            roots.extend(
                f"{letter}:\\"
                for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                if Path(f"{letter}:\\").is_dir()
            )
        else:
            roots.append("/")
        return {
            "path": str(path),
            "parent": str(path.parent) if path.parent != path else None,
            "folders": sorted(directories, key=lambda item: item["name"].casefold()),
            "roots": roots,
        }

    def info(self) -> dict[str, Any]:
        with self.lock:
            state = self.active_state()
            if state is not None:
                Database(state).check()
            return {
                "root": load_settings(state).root if state is not None else None,
                "state": str(state) if state is not None else None,
                "running": self.thread is not None and self.thread.is_alive(),
                "error": self.error,
            }

    def start(self) -> None:
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                return
            state = self.active_state()
            if state is None:
                return
            try:
                service = WatchService(state, lambda events: self._error(None), self._error)
            except (OSError, ValueError) as exc:
                self.error = str(exc)
                return
            self.stop = threading.Event()
            stop = self.stop
            self.error = None

            def run() -> None:
                try:
                    service.run(stop)
                except Exception as exc:
                    self._error(str(exc))
                finally:
                    service.startup_complete.set()

            self.thread = threading.Thread(target=run, name="traceguard-monitor", daemon=True)
            self.thread.start()
            # Do not report successful startup before Watchdog has subscribed.
            if not service.startup_complete.wait(5) or not service.ready.is_set():
                stop.set()
                self.thread.join(timeout=10)
                self.error = self.error or "The folder monitor could not start. Try again."

    def _error(self, message: str | None) -> None:
        self.error = message

    def close(self) -> None:
        with self.lock:
            self.stop.set()
            if self.thread is not None:
                self.thread.join(timeout=35)
                if self.thread.is_alive():
                    raise RuntimeError("Previous monitor is still stopping; try again shortly")
                self.thread = None

    def select(self, value: str) -> dict[str, Any]:
        with self.lock:
            root = self.directory(value)
            current = self.active_state()
            settings = Settings(root=str(root))
            if current is not None:
                Database(current).check()
            if root in self.base.parents:
                settings.excludes.append(self.base.relative_to(root).as_posix())
            if current is None:
                target = self.base
            elif Path(load_settings(self.base).root) == root:
                target = self.base
            else:
                identity = hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()
                target = self.base / "locations" / identity
            if (target / "config.json").exists():
                Database(target).check()
                if Path(load_settings(target).root) != root:
                    raise ValueError("Stored monitoring location does not match this folder")
            else:
                # Finish validation and hashing before stopping the current monitor.
                records = snapshot(settings, self.base)
                Database(target).initialize(settings, records)
            self.close()
            with Database(self.base).transaction() as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS monitoring_selection "
                    "(id INTEGER PRIMARY KEY CHECK(id=1), location TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT OR REPLACE INTO monitoring_selection VALUES(1,?)",
                    ("." if target == self.base else target.name,),
                )
            self.start()
            return self.info()
