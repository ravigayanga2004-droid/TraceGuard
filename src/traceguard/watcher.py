"""Watchdog triggers debounced scans; periodic scans reconcile dropped events."""

import threading
import time
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from traceguard.baseline import scan
from traceguard.config import load_settings
from traceguard.database import Database
from traceguard.models import Event
from traceguard.scanner import ScanError, excluded


class WatchService:
    def __init__(
        self,
        state: Path,
        on_events: Callable[[list[Event]], None],
        on_error: Callable[[str], None] = print,
    ):
        Database(state).check()
        self.state = state
        self.settings = load_settings(state)
        self.on_events = on_events
        self.on_error = on_error
        self.ready = threading.Event()
        self.dirty = threading.Event()
        self.last_change = 0.0

    def run(self, stop: threading.Event) -> None:
        service = self
        root = Path(self.settings.root)

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event: FileSystemEvent) -> None:
                if event.event_type not in {"created", "modified", "deleted", "moved"}:
                    return
                for value in (event.src_path, getattr(event, "dest_path", "")):
                    if not value:
                        continue
                    path = Path(str(value)).absolute()
                    if path == root or (
                        root in path.parents
                        and not excluded(path, root, service.state, service.settings.excludes)
                    ):
                        service.last_change = time.monotonic()
                        service.dirty.set()

        observer = Observer()
        observer.schedule(Handler(), str(root), recursive=True)
        observer.start()
        self.ready.set()
        next_scan = 0.0
        try:
            while not stop.is_set():
                now = time.monotonic()
                if now >= next_scan or (
                    self.dirty.is_set() and now - self.last_change >= self.settings.debounce_seconds
                ):
                    self.dirty.clear()
                    try:
                        self.on_events(scan(self.state))
                    except ScanError as exc:
                        self.on_error(str(exc))
                    next_scan = time.monotonic() + self.settings.reconcile_seconds
                stop.wait(0.1)
        finally:
            observer.stop()
            observer.join(timeout=10)
            self.ready.clear()
