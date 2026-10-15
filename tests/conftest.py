from pathlib import Path

import pytest

from traceguard.database import Database
from traceguard.models import Settings
from traceguard.scanner import snapshot


@pytest.fixture
def project(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "original.txt").write_text("trusted\n", encoding="utf-8")
    state = tmp_path / "state"
    settings = Settings(
        root=str(root), reconcile_seconds=0.3, debounce_seconds=0.1, mass_change_threshold=4
    )
    Database(state).initialize(settings, snapshot(settings, state))
    return root, state
