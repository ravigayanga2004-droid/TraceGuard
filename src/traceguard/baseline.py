"""Baseline approvals and scanning share an atomic database transaction."""

from pathlib import Path

from traceguard.config import load_settings
from traceguard.database import Database, add_events, read_snapshot, save_snapshot
from traceguard.detection import differences
from traceguard.models import Event, utcnow
from traceguard.scanner import snapshot


def scan(state: Path) -> list[Event]:
    with Database(state).transaction() as connection:
        settings = load_settings(state)
        current = snapshot(settings, state)
        changes = differences(read_snapshot(connection, "observed"), current)
        add_events(connection, changes, settings)
        save_snapshot(connection, "observed", current)
    return changes


def approve(state: Path, note: str) -> int:
    if not note.strip():
        raise ValueError("An approval note is required")
    with Database(state).transaction() as connection:
        settings = load_settings(state)
        current = snapshot(settings, state)
        changes = differences(read_snapshot(connection, "observed"), current)
        add_events(connection, changes, settings)
        save_snapshot(connection, "observed", current)
        save_snapshot(connection, "baseline", current)
        connection.execute(
            "INSERT INTO approvals(timestamp,note,file_count) VALUES(?,?,?)",
            (utcnow(), note.strip(), len(current)),
        )
    return len(current)
