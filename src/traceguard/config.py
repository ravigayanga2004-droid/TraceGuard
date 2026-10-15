"""State path and initialization helpers."""

import os
from pathlib import Path

from traceguard.models import Settings


def state_directory(value: Path | None = None) -> Path:
    return (value or Path(os.environ.get("TRACEGUARD_STATE", ".traceguard"))).resolve()


def load_settings(state: Path) -> Settings:
    path = state / "config.json"
    if not path.is_file():
        raise ValueError("Not initialized. Run traceguard init DIRECTORY first.")
    return Settings.model_validate_json(path.read_text(encoding="utf-8"))
