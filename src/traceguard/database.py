"""SQLite persistence. All clients serialize verification, transactions, and sealing."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from traceguard.integrity import IntegrityError, digest, seal, state_lock, verify
from traceguard.models import Event, FileRecord, Settings, utcnow
from traceguard.severity import score_event

SCHEMA = """
CREATE TABLE snapshots (
    kind TEXT NOT NULL, path TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(kind,path)
);
CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
    incident_id INTEGER NOT NULL, record TEXT NOT NULL);
CREATE TABLE incidents (id INTEGER PRIMARY KEY, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, score INTEGER NOT NULL, event_count INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open');
CREATE TABLE approvals (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
    note TEXT NOT NULL, file_count INTEGER NOT NULL);
"""


class Database:
    def __init__(self, state: Path):
        self.state = state.resolve()
        self.path = self.state / "traceguard.db"

    def initialize(self, settings: Settings, records: dict[str, FileRecord]) -> None:
        with state_lock(self.state):
            if any(p.name != "state.lock" for p in self.state.iterdir()):
                raise ValueError("State directory is not empty; refusing to overwrite it")
            (self.state / "config.json").write_text(
                settings.model_dump_json(indent=2), encoding="utf-8"
            )
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.executescript(SCHEMA)
                save_snapshot(connection, "baseline", records)
                save_snapshot(connection, "observed", records)
                connection.execute(
                    "INSERT INTO approvals(timestamp,note,file_count) VALUES(?,?,?)",
                    (utcnow(), "Initial trusted baseline", len(records)),
                )
            seal(self.state, initialize=True)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with state_lock(self.state):
            if not self.path.is_file():
                raise IntegrityError("Database missing; restore a trusted backup")
            verify(self.state)
            # mode=rw prevents SQLite from silently recreating a deleted database.
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                # Retain SQLite's exclusive lock through commit and sealing so an
                # external SQL client cannot write between verification and sealing.
                connection.execute("PRAGMA locking_mode=EXCLUSIVE")
                connection.execute("BEGIN EXCLUSIVE")
                verify(self.state)
                configuration = (self.state / "config.json").read_bytes()
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise IntegrityError("SQLite integrity check failed")
                yield connection
                if (self.state / "config.json").read_bytes() != configuration:
                    raise IntegrityError("Configuration changed during transaction")
                connection.commit()
                seal(self.state)
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    def check(self) -> None:
        with self.transaction():
            pass

    def acknowledge_tampering(self) -> None:
        """Explicit recovery, preserving a critical incident after inspection."""
        with state_lock(self.state):
            # Never recreate a deleted database or bypass structural corruption.
            if not self.path.is_file():
                raise IntegrityError("Database missing; restore a trusted backup")
            # Validate key/config availability before making any recovery writes.
            digest(self.state)
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA locking_mode=EXCLUSIVE")
                connection.execute("BEGIN EXCLUSIVE")
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise IntegrityError("Database corrupt; restore a trusted backup")
                settings = Settings.model_validate_json(
                    (self.state / "config.json").read_text(encoding="utf-8")
                )
                add_events(
                    connection, [Event(kind="database_tampering", path="traceguard.db")], settings
                )
                connection.commit()
                seal(self.state)
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()


def read_snapshot(connection: sqlite3.Connection, kind: str) -> dict[str, FileRecord]:
    return {
        row[0]: FileRecord.model_validate_json(row[1])
        for row in connection.execute(
            "SELECT path,record FROM snapshots WHERE kind=? ORDER BY path", (kind,)
        )
    }


def save_snapshot(
    connection: sqlite3.Connection, kind: str, records: dict[str, FileRecord]
) -> None:
    connection.execute("DELETE FROM snapshots WHERE kind=?", (kind,))
    connection.executemany(
        "INSERT INTO snapshots VALUES(?,?,?)",
        [(kind, path, item.model_dump_json()) for path, item in sorted(records.items())],
    )


def add_events(connection: sqlite3.Connection, events: list[Event], settings: Settings) -> None:
    if not events:
        return
    from datetime import UTC, datetime, timedelta

    cutoff = (datetime.now(UTC) - timedelta(seconds=settings.incident_window_seconds)).isoformat()
    incident = connection.execute(
        "SELECT * FROM incidents WHERE last_seen>=? AND status='open' ORDER BY id DESC LIMIT 1",
        (cutoff,),
    ).fetchone()
    now = utcnow()
    if incident:
        incident_id = incident["id"]
    else:
        cursor = connection.execute(
            "INSERT INTO incidents(first_seen,last_seen,score,event_count) VALUES(?,?,0,0)",
            (now, now),
        )
        incident_id = cursor.lastrowid
    recent = connection.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp>=?", (cutoff,)
    ).fetchone()[0]
    mass = recent + len(events) >= settings.mass_change_threshold
    for event in events:
        score_event(event, mass)
        event.incident_id = incident_id
        cursor = connection.execute(
            "INSERT INTO events(timestamp,incident_id,record) VALUES(?,?,?)",
            (event.timestamp, incident_id, event.model_dump_json()),
        )
        event.id = cursor.lastrowid
        connection.execute(
            "UPDATE events SET record=? WHERE id=?", (event.model_dump_json(), event.id)
        )
    # Escalate earlier events too when a burst spans several scans.
    if mass:
        for row in connection.execute("SELECT id,record FROM events WHERE timestamp>=?", (cutoff,)):
            previous = score_event(Event.model_validate_json(row[1]), True)
            connection.execute(
                "UPDATE events SET record=? WHERE id=?", (previous.model_dump_json(), row[0])
            )
    for row in connection.execute("SELECT id FROM incidents").fetchall():
        scores = [
            json.loads(item[0])["score"]
            for item in connection.execute(
                "SELECT record FROM events WHERE incident_id=?", (row[0],)
            )
        ]
        connection.execute(
            "UPDATE incidents SET score=?,event_count=? WHERE id=?",
            (max(scores, default=0), len(scores), row[0]),
        )
    connection.execute("UPDATE incidents SET last_seen=? WHERE id=?", (now, incident_id))
