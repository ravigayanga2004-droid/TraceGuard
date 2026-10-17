"""State path and initialization helpers."""

import os
from pathlib import Path

from traceguard.models import Settings


def state_directory(value: Path | None = None, *, selected: bool = True) -> Path:
    state = (value or Path(os.environ.get("TRACEGUARD_STATE", ".traceguard"))).resolve()
    return selected_state(state) if selected and (state / "config.json").exists() else state


def selected_state(state: Path) -> Path:
    """Resolve the dashboard selection through the integrity-protected catalog."""
    from traceguard.database import Database

    with Database(state).transaction() as connection:
        if not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='monitoring_selection'"
        ).fetchone():
            return state
        row = connection.execute("SELECT location FROM monitoring_selection WHERE id=1").fetchone()
        if row is None or row[0] == ".":
            return state
        location = row[0]
        if len(location) != 64 or any(c not in "0123456789abcdef" for c in location):
            raise ValueError("Invalid monitoring location in catalog")
        return state / "locations" / location


def load_settings(state: Path) -> Settings:
    path = state / "config.json"
    if not path.is_file():
        raise ValueError("Not initialized. Run traceguard init DIRECTORY first.")
    return Settings.model_validate_json(path.read_text(encoding="utf-8"))
