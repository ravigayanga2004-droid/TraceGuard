import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from traceguard.api.app import create_app
from traceguard.baseline import scan
from traceguard.cli import app
from traceguard.config import selected_state
from traceguard.database import Database
from traceguard.reporting import report_data
from traceguard.scanner import ScanError

HEADERS = {"X-TraceGuard-Request": "1", "Origin": "http://127.0.0.1"}


def choose(client: TestClient, root: Path):
    return client.post("/api/monitoring", json={"path": str(root)}, headers=HEADERS)


def test_first_folder_selection_and_restart(tmp_path: Path) -> None:
    root = tmp_path / "chosen"
    root.mkdir()
    (root / "trusted.txt").write_text("trusted")
    state = tmp_path / "state"
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/monitoring").json()["root"] is None
        assert client.get("/api/status").status_code == 400
        response = choose(client, root)
        assert response.status_code == 200, response.text
        assert response.json()["root"] == str(root)
        assert response.json()["running"]
        assert client.get("/api/status").json()["baseline_files"] == 1
        (root / "new.txt").write_text("new")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if client.get("/api/events").json():
                break
            time.sleep(0.05)
        assert client.get("/api/events").json()[0]["path"] == "new.txt"
    # A new app restores the selection and starts monitoring without rebaselining.
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        assert client.get("/api/monitoring").json()["running"]
        assert client.get("/api/status").json()["baseline_files"] == 1
        assert client.get("/api/status").json()["drift_count"] == 1


def test_switch_preserves_history_and_cli_uses_selection(project, tmp_path: Path) -> None:
    root, state = project
    (root / "first.txt").write_text("first location event")
    scan(state)
    other = tmp_path / "other location"
    other.mkdir()
    (other / "second.txt").write_text("second location baseline")
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        response = choose(client, other)
        assert response.status_code == 200, response.text
        location_state = Path(response.json()["state"])
        assert selected_state(state) == location_state
        assert client.get("/api/events").json() == []
        assert client.get("/api/status").json()["baseline_files"] == 1
        (other / "third.txt").write_text("third")
        result = CliRunner().invoke(app, ["scan", "--state", str(state)])
        assert result.exit_code == 0, result.output
        assert report_data(location_state)["events"][0]["path"] == "third.txt"
        assert choose(client, root).status_code == 200
        assert client.get("/api/events").json()[0]["path"] == "first.txt"
        assert choose(client, other).status_code == 200
        assert client.get("/api/events").json()[0]["path"] == "third.txt"
        assert client.get("/api/status").json()["drift_count"] == 1
        assert client.get("/api/report/json").json()["events"][0]["path"] == "third.txt"
    Database(state).check()
    Database(location_state).check()


def test_folder_browser_and_invalid_selections(project, tmp_path: Path, monkeypatch) -> None:
    root, state = project
    (root / "child folder").mkdir()
    other = tmp_path / "other"
    other.mkdir()
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        listing = client.get("/api/folders", params={"path": str(root)}).json()
        assert listing["path"] == str(root)
        assert listing["parent"] == str(root.parent)
        assert listing["folders"] == [{"name": "child folder", "path": str(root / "child folder")}]
        for invalid in (
            "",
            "relative/folder",
            str(root / "missing"),
            str(root / "original.txt"),
            str(state),
            str(state / "locations"),
        ):
            assert client.post(
                "/api/monitoring", json={"path": invalid}, headers=HEADERS
            ).status_code in {400, 422}
            assert client.get("/api/monitoring").json()["root"] == str(root)
            assert client.get("/api/monitoring").json()["running"]

        def failed_scan(*args):
            raise ScanError("Incomplete scan; previous state preserved")

        monkeypatch.setattr("traceguard.monitoring.snapshot", failed_scan)
        assert choose(client, other).status_code == 400
        assert client.get("/api/monitoring").json()["root"] == str(root)
        assert client.get("/api/monitoring").json()["running"]


def test_selection_rejects_cross_origin_requests(project) -> None:
    root, state = project
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        for headers in (
            {},
            {"Origin": "https://attacker.invalid"},
            {"X-TraceGuard-Request": "1", "Origin": "https://attacker.invalid"},
            {"X-TraceGuard-Request": "1", "Origin": "null"},
        ):
            assert (
                client.post(
                    "/api/monitoring", json={"path": str(root)}, headers=headers
                ).status_code
                == 403
            )
        assert (
            client.options(
                "/api/monitoring",
                headers={
                    "Origin": "https://attacker.invalid",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "x-traceguard-request",
                },
            ).status_code
            == 405
        )
        assert choose(client, root).status_code == 200


@pytest.mark.parametrize("damage", ["catalog", "profile"])
def test_selection_preserves_tamper_evidence(project, tmp_path: Path, damage: str) -> None:
    root, state = project
    other = tmp_path / "other"
    other.mkdir()
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        profile = Path(choose(client, other).json()["state"])
    damaged = state if damage == "catalog" else profile
    (damaged / "integrity.seal").write_text("tampered")
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        assert client.get("/api/monitoring").status_code == 409
        assert choose(client, root).status_code == 409
    result = CliRunner().invoke(app, ["integrity", "--state", str(state), "--acknowledge", "--yes"])
    assert result.exit_code == 0, result.output
    assert report_data(damaged)["events"][0]["kind"] == "database_tampering"


def test_profile_excludes_all_state_when_monitoring_parent(project) -> None:
    root, state = project
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        response = choose(client, root.parent)
        assert response.status_code == 200, response.text
        scan(Path(response.json()["state"]))
        assert client.get("/api/events").json() == []
        assert client.get("/api/status").json()["baseline_files"] == 1


def test_serve_allows_first_run_setup(tmp_path: Path, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr("traceguard.cli.uvicorn.run", lambda app, **kwargs: calls.append(kwargs))
    result = CliRunner().invoke(app, ["serve", "--state", str(tmp_path / "new-state")])
    assert result.exit_code == 0, result.output
    assert calls[0]["host"] == "127.0.0.1"


def test_select_folder_with_windows_command_shims(project, tmp_path: Path) -> None:
    _, state = project
    root = tmp_path / "projects"
    shims = root / "Car-Game-Prototype" / "node_modules" / ".bin"
    shims.mkdir(parents=True)
    command = shims / "playwright.CMD"
    command.write_bytes(b"@echo off\r\nrem harmless fixture\r\n")
    relative = "Car-Game-Prototype/node_modules/.bin/playwright.CMD"
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        response = choose(client, root)
        assert response.status_code == 200, response.text
        assert response.json()["running"]
        assert response.json()["error"] is None
        selected = Path(response.json()["state"])
        assert client.get("/api/status").json()["baseline_files"] == 1
        assert scan(selected) == []
        command.write_bytes(b"@echo off\r\nrem changed fixture\r\n")
        scan(selected)
        events = client.get("/api/events").json()
        assert any(event["path"] == relative and event["kind"] == "modified" for event in events)
