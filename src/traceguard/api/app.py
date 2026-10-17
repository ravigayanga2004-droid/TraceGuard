"""Local dashboard, folder selection, and integrity-checked audit reads."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from traceguard.database import Database
from traceguard.integrity import IntegrityError
from traceguard.monitoring import Monitoring
from traceguard.reporting import render_report, report_data
from traceguard.scanner import ScanError


class LocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=32768)


def create_app(state: Path) -> FastAPI:
    monitoring = Monitoring(state)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Preserve access to the dashboard and its actionable integrity errors.
        try:
            monitoring.start()
        except IntegrityError as exc:
            monitoring.error = str(exc)
        try:
            yield
        finally:
            monitoring.close()

    app = FastAPI(
        title="TraceGuard local API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        telemetry={
            "tracing": False,
            "metrics": False,
            "logs": False,
            "operation_spans": False,
            "auto_configure": False,
        },
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    def active_state() -> Path:
        target = monitoring.active_state()
        if target is None:
            raise HTTPException(status_code=400, detail="Choose a monitoring folder first.")
        return target

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        if request.method == "POST" and request.url.path == "/api/monitoring":
            # A custom header requires a CORS preflight; cross-site forms cannot set it.
            origin = request.headers.get("origin")
            if request.headers.get("x-traceguard-request") != "1" or (
                origin is not None and origin != str(request.base_url).rstrip("/")
            ):
                return JSONResponse(
                    status_code=403, content={"detail": "Local dashboard request required"}
                )
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    @app.exception_handler(IntegrityError)
    async def integrity_failure(request: Request, exc: IntegrityError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc), "integrity": "failed"})

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return (Path(__file__).parent.parent / "web" / "index.html").read_text(encoding="utf-8")

    @app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
    def docs() -> str:
        return (
            "<!doctype html><html lang='en'><meta charset='utf-8'><title>TraceGuard API</title>"
            "<body style='font:18px system-ui;max-width:900px;margin:3rem auto'>"
            "<h1>TraceGuard local API</h1><p>Audit endpoints are read-only. "
            "No authentication is provided; access is restricted to loopback.</p>"
            "<ul><li><a href='/api/status'>/api/status</a> — summary and latest approval</li>"
            "<li><a href='/api/monitoring'>/api/monitoring</a> "
            "— selected folder and monitor health</li>"
            "<li><a href='/api/folders'>/api/folders</a> — local folder browser</li>"
            "<li>POST /api/monitoring — select a folder with JSON {path: absolute_path} "
            "and X-TraceGuard-Request: 1; browser Origin must match this server</li>"
            "<li><a href='/api/events'>/api/events?limit=100&amp;offset=0</a> — newest first, "
            "limit 1–1000</li>"
            "<li><a href='/api/incidents'>/api/incidents</a> — grouped changes</li>"
            "<li><a href='/api/drift'>/api/drift</a> — observed versus approved state</li>"
            "<li><a href='/api/integrity'>/api/integrity</a> — local integrity verification</li>"
            "<li>/api/report/{format} — json, markdown, html</li>"
            "<li><a href='/openapi.json'>/openapi.json</a> — machine-readable schema</li></ul>"
            "<p>Invalid queries return 422; integrity violations return 409. "
            "The server monitors the selected folder while it is running.</p>"
            "<a href='/'>Back to dashboard</a></body></html>"
        )

    @app.get("/api/monitoring")
    def monitoring_status() -> dict[str, Any]:
        return monitoring.info()

    @app.get("/api/folders")
    def folders(path: str | None = None) -> dict[str, Any]:
        try:
            return monitoring.folders(path)
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/monitoring")
    def select_folder(selection: LocationRequest) -> dict[str, Any]:
        try:
            return monitoring.select(selection.path)
        except (ValueError, OSError, ScanError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            if isinstance(exc, IntegrityError):
                raise
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        data = report_data(active_state())
        return {
            "integrity": "ok",
            "baseline_files": data["baseline_files"],
            "observed_files": data["observed_files"],
            "drift_count": len(data["drift"]),
            "event_count": len(data["events"]),
            "incident_count": len(data["incidents"]),
            "last_approval": data["approvals"][0] if data["approvals"] else None,
        }

    @app.get("/api/events")
    def events(
        limit: int = Query(default=100, ge=1, le=1000), offset: int = Query(default=0, ge=0)
    ) -> list[dict[str, Any]]:
        return report_data(active_state())["events"][offset : offset + limit]  # type: ignore[no-any-return]

    @app.get("/api/incidents")
    def incidents() -> list[dict[str, Any]]:
        return report_data(active_state())["incidents"]  # type: ignore[no-any-return]

    @app.get("/api/drift")
    def drift() -> list[dict[str, Any]]:
        return report_data(active_state())["drift"]  # type: ignore[no-any-return]

    @app.get("/api/integrity")
    def integrity() -> dict[str, str]:
        Database(active_state()).check()
        return {"integrity": "ok"}

    @app.get("/api/report/{format}")
    def report(format: str) -> Response:
        if format not in {"json", "markdown", "html"}:
            return JSONResponse(status_code=400, content={"detail": "Unknown report format"})
        media = {"json": "application/json", "markdown": "text/markdown", "html": "text/html"}
        return Response(
            render_report(report_data(active_state()), format), media_type=media[format]
        )

    return app
