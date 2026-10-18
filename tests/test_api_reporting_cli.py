import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from traceguard.api.app import create_app
from traceguard.baseline import scan
from traceguard.cli import app
from traceguard.reporting import render_report, report_data

runner = CliRunner()


def test_api_readonly_limits_host_and_exports(project: tuple[Path, Path]) -> None:
    root, state = project
    (root / "new.txt").write_text("new")
    scan(state)
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "TraceGuard" in home.text
        assert client.get("/docs").status_code == 200
        assert "https://" not in client.get("/docs").text
        assert client.get("/openapi.json").status_code == 200
        assert home.headers["X-Frame-Options"] == "DENY"
        assert client.get("/api/status").json()["event_count"] == 1
        assert len(client.get("/api/events").json()) == 1
        assert client.get("/api/events?offset=1").json() == []
        assert client.get("/api/events?limit=1001").status_code == 422
        assert len(client.get("/api/incidents").json()) == 1
        assert len(client.get("/api/drift").json()) == 1
        assert client.get("/api/integrity").json() == {"integrity": "ok"}
        for format in ("json", "markdown", "html"):
            assert client.get(f"/api/report/{format}").status_code == 200
        assert client.get("/api/report/nope").status_code == 400
        assert client.post("/api/approve").status_code in {404, 405}
        assert client.get("/api/status", headers={"host": "attacker.invalid"}).status_code == 400
        assert (
            "access-control-allow-origin"
            not in client.get("/api/events", headers={"origin": "https://attacker.invalid"}).headers
        )


def test_api_tamper_error(project: tuple[Path, Path]) -> None:
    _, state = project
    (state / "integrity.seal").write_text("invalid")
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        response = client.get("/api/status")
        assert response.status_code == 409
        assert response.json()["integrity"] == "failed"


def test_api_corrupt_database_returns_integrity_error(project: tuple[Path, Path]) -> None:
    _, state = project
    (state / "traceguard.db").write_bytes(b"corrupted database")
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        assert client.get("/api/status").status_code == 409


def test_report_escaping_and_formats(project: tuple[Path, Path]) -> None:
    _, state = project
    data = report_data(state)
    data["events"] = [
        {
            "timestamp": "now",
            "kind": "created",
            "path": "<script>alert(1)</script>|",
            "severity": "low",
            "score": 10,
            "reasons": ["test"],
        }
    ]
    html = render_report(data, "html")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    markdown = render_report(data, "markdown")
    assert "<script>" not in markdown
    assert "&#124;" in markdown
    data["events"][0]["path"] = "![image](https://example.invalid/tracking)"
    assert "![image]" not in render_report(data, "markdown")
    data["events"][0]["path"] = "<script>alert(1)</script>|"
    assert json.loads(render_report(data, "json"))["events"][0]["path"].startswith("<script>")
    with pytest.raises(ValueError):
        render_report(data, "bad")


def test_cli_complete_flow(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    root.mkdir()
    state = tmp_path / "state"
    args = ["--state", str(state)]
    result = runner.invoke(app, ["init", str(root), *args])
    assert result.exit_code == 0, result.output
    assert runner.invoke(app, ["init", str(root), *args]).exit_code == 1
    (root / "sample.py").write_text("# harmless\n")
    result = runner.invoke(app, ["scan", *args])
    assert result.exit_code == 0, result.output
    assert runner.invoke(app, ["status", *args]).exit_code == 0
    assert runner.invoke(app, ["integrity", *args]).exit_code == 0
    result = runner.invoke(app, ["approve", "--note", "test approval", "--yes", *args])
    assert result.exit_code == 0, result.output
    assert report_data(state)["drift"] == []
    for format in ("json", "markdown", "html"):
        output = tmp_path / f"report.{format}"
        result = runner.invoke(app, ["report", "--format", format, "--output", str(output), *args])
        assert result.exit_code == 0, result.output
        assert output.stat().st_size > 0
        assert runner.invoke(app, ["report", "--output", str(output), *args]).exit_code == 1


def test_cli_safe_failures(tmp_path: Path, project: tuple[Path, Path]) -> None:
    root, state = project
    args = ["--state", str(state)]
    assert runner.invoke(app, ["scan", "--state", str(tmp_path / "missing")]).exit_code == 1
    assert runner.invoke(app, ["approve", "--note", "review", *args], input="n\n").exit_code != 0
    for host in ("0.0.0.0", "192.168.1.2", "example.com", "127.0.0.2"):
        assert runner.invoke(app, ["serve", "--host", host, *args]).exit_code == 1
    result = runner.invoke(app, ["report", "--output", str(state / "bad.html"), *args])
    assert result.exit_code == 1
    assert not (state / "bad.html").exists()
    assert runner.invoke(app, ["report", "--format", "bad", *args]).exit_code == 1
    assert runner.invoke(app, ["init", str(root), "--state", str(root.parent)]).exit_code == 1


def test_serve_defaults_are_loopback(project: tuple[Path, Path], monkeypatch) -> None:
    _, state = project
    calls = []
    monkeypatch.setattr("traceguard.cli.uvicorn.run", lambda app, **kw: calls.append(kw))
    result = runner.invoke(app, ["serve", "--state", str(state)])
    assert result.exit_code == 0, result.output
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8765


def test_framework_telemetry_is_disabled(project: tuple[Path, Path], monkeypatch) -> None:
    _, state = project
    monkeypatch.setenv("FASTAPI_OTEL_AUTO_CONFIGURE", "true")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://example.invalid")
    application = create_app(state)
    # Newer FastAPI supports native telemetry; older supported versions have no exporter.
    configuration = getattr(application, "_telemetry", None)
    if configuration is not None:
        assert not any(
            configuration[name] for name in ("tracing", "metrics", "logs", "auto_configure")
        )
    with TestClient(application, base_url="http://127.0.0.1") as client:
        assert client.get("/api/status").status_code == 200


def test_dashboard_uses_one_consistent_audit_read(project, monkeypatch) -> None:
    from unittest.mock import Mock

    root, state = project
    (root / "new.txt").write_text("new")
    scan(state)
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        read = Mock(wraps=report_data)
        monkeypatch.setattr("traceguard.api.app.report_data", read)
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["status"]["event_count"] == len(data["events"]) == 1
        assert data["status"]["incident_count"] == len(data["incidents"]) == 1
        assert data["status"]["drift_count"] == len(data["drift"]) == 1
        read.assert_called_once_with(state)


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (PermissionError("State is unreadable"), 503),
        (TimeoutError("State is busy; try again"), 503),
        (sqlite3.OperationalError("database is locked"), 503),
        (ValueError("Invalid monitoring location in catalog"), 400),
        (sqlite3.DatabaseError("Database corrupt"), 409),
    ],
)
def test_api_state_errors_return_actionable_json(project, monkeypatch, error, status) -> None:
    _, state = project

    def failed_read(*args):
        raise error

    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        monkeypatch.setattr("traceguard.api.app.report_data", failed_read)
        for endpoint in ("/api/status", "/api/dashboard", "/api/events", "/api/report/json"):
            response = client.get(endpoint)
            assert response.status_code == status
            assert response.json()["detail"] == str(error)
            assert response.headers["Cache-Control"] == "no-store"


def test_dashboard_remains_available_when_state_is_busy(project, monkeypatch) -> None:
    def busy(*args):
        raise TimeoutError("State is busy; try again")

    _, state = project
    monkeypatch.setattr("traceguard.monitoring.Monitoring.active_state", busy)
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        assert client.get("/").status_code == 200
        response = client.get("/api/monitoring")
        assert response.status_code == 503
        assert response.json()["detail"] == "State is busy; try again"
