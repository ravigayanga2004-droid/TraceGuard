import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from traceguard.baseline import scan
from traceguard.database import Database
from traceguard.integrity import IntegrityError
from traceguard.reporting import report_data


def test_sql_tampering_blocks_operations_and_can_be_acknowledged(
    project: tuple[Path, Path],
) -> None:
    _, state = project
    with closing(sqlite3.connect(state / "traceguard.db")) as connection, connection:
        connection.execute("UPDATE approvals SET note='external edit'")
    with pytest.raises(IntegrityError):
        scan(state)
    with pytest.raises(IntegrityError):
        report_data(state)
    Database(state).acknowledge_tampering()
    data = report_data(state)
    assert data["events"][0]["kind"] == "database_tampering"
    assert data["events"][0]["severity"] == "critical"
    Database(state).check()


@pytest.mark.parametrize(
    "name", ["traceguard.db", "config.json", "integrity.key", "integrity.seal"]
)
def test_missing_state_detected(project: tuple[Path, Path], name: str) -> None:
    _, state = project
    (state / name).unlink()
    with pytest.raises(IntegrityError):
        Database(state).check()
    assert not (state / name).exists()


def test_config_changes_detected(project: tuple[Path, Path]) -> None:
    _, state = project
    with (state / "config.json").open("a") as stream:
        stream.write(" ")
    with pytest.raises(IntegrityError):
        Database(state).check()


def test_corrupt_database_not_acknowledged(project: tuple[Path, Path]) -> None:
    _, state = project
    (state / "traceguard.db").write_bytes(b"broken")
    with pytest.raises(sqlite3.DatabaseError):
        Database(state).acknowledge_tampering()


def test_missing_key_recovery_does_not_write_database(project: tuple[Path, Path]) -> None:
    _, state = project
    original = (state / "traceguard.db").read_bytes()
    (state / "integrity.key").unlink()
    with pytest.raises(OSError):
        Database(state).acknowledge_tampering()
    assert (state / "traceguard.db").read_bytes() == original
