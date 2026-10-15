"""TraceGuard command-line entry points."""

import functools
import ipaddress
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from traceguard import baseline
from traceguard.api.app import create_app
from traceguard.config import state_directory
from traceguard.database import Database
from traceguard.integrity import IntegrityError
from traceguard.models import Settings
from traceguard.notifications import Notifier
from traceguard.reporting import render_report, report_data
from traceguard.scanner import ScanError, is_link, snapshot
from traceguard.watcher import WatchService

app = typer.Typer(no_args_is_help=True, help="Local-first file integrity monitoring.")
console = Console()
State = Annotated[Path | None, typer.Option(help="Local state directory (default .traceguard).")]


def friendly_errors(function: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except (ValueError, OSError, ScanError, IntegrityError, sqlite3.DatabaseError) as exc:
            console.print(f"Error: {exc}", style="red", markup=False)
            raise typer.Exit(1) from exc

    return wrapped


@app.command()
@friendly_errors
def init(
    directory: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    state: State = None,
    exclude: Annotated[list[str] | None, typer.Option(help="Repeatable glob exclusion.")] = None,
    interval: Annotated[float, typer.Option(min=0.2)] = 30,
    mass_threshold: Annotated[int, typer.Option(min=2)] = 20,
) -> None:
    """Create an initial trusted baseline; existing state is never overwritten."""
    directory = directory.absolute()
    if is_link(directory):
        raise ValueError("Monitoring root must not be a symlink or junction")
    target = state_directory(state)
    root = directory.resolve()
    if root == target or target in root.parents:
        raise ValueError("Monitoring root cannot be inside the state directory")
    settings = Settings(
        root=str(root), reconcile_seconds=interval, mass_change_threshold=mass_threshold
    )
    if exclude:
        settings.excludes.extend(exclude)
    records = snapshot(settings, target)
    Database(target).initialize(settings, records)
    console.print(f"Trusted baseline created: {len(records)} files. State: {target}", markup=False)


@app.command()
@friendly_errors
def scan(state: State = None) -> None:
    """Scan once, record changes, and preserve the approved baseline."""
    events = baseline.scan(state_directory(state))
    Notifier()(events)
    console.print(f"Scan complete: {len(events)} changes")


@app.command()
@friendly_errors
def approve(
    note: Annotated[str, typer.Option(help="Required reason for trusting current files.")],
    state: State = None,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm baseline replacement.")] = False,
) -> None:
    """Explicitly approve current files as the new trusted baseline."""
    if not yes:
        typer.confirm("Trust all current files and replace the approved baseline?", abort=True)
    count = baseline.approve(state_directory(state), note)
    console.print(f"Approved {count} files; audit history retained")


@app.command()
@friendly_errors
def status(state: State = None) -> None:
    """Show baseline drift, event counts, and incident counts."""
    data = report_data(state_directory(state))
    table = Table("Metric", "Value")
    for key in ("integrity", "baseline_files", "observed_files"):
        table.add_row(key, str(data[key]))
    for key in ("drift", "events", "incidents"):
        table.add_row(key, str(len(data[key])))
    console.print(table)


@app.command()
@friendly_errors
def watch(state: State = None, desktop: bool = False, email: bool = False) -> None:
    """Watch continuously with periodic reconciliation; Ctrl+C stops cleanly."""
    notify = Notifier(desktop=desktop, email=email)
    service = WatchService(
        state_directory(state),
        notify,
        lambda message: console.print(message, style="yellow", markup=False),
    )
    console.print("Monitoring locally. Press Ctrl+C to stop.")
    stop = threading.Event()
    try:
        service.run(stop)
    except KeyboardInterrupt:
        stop.set()
        console.print("Monitoring stopped")


@app.command()
@friendly_errors
def serve(
    state: State = None,
    host: str = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8765,
) -> None:
    """Serve the read-only dashboard on loopback. Run watch separately."""
    try:
        host = str(ipaddress.ip_address(host))
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("Dashboard binding is restricted to 127.0.0.1 or ::1")
    except ValueError as exc:
        raise ValueError("Use a loopback IP such as 127.0.0.1 or ::1") from exc
    target = state_directory(state)
    Database(target).check()
    uvicorn.run(create_app(target), host=host, port=port, access_log=False)


@app.command()
@friendly_errors
def report(state: State = None, format: str = "html", output: Path | None = None) -> None:
    """Export JSON, Markdown, or HTML. Existing output files are never overwritten."""
    target = state_directory(state)
    if output is None:
        suffix = {"json": "json", "markdown": "md", "html": "html"}.get(format)
        if suffix is None:
            raise ValueError("Format must be json, markdown, or html")
        from datetime import UTC, datetime

        output = Path("reports") / f"traceguard-{datetime.now(UTC):%Y%m%dT%H%M%S%f}.{suffix}"
    destination = output.resolve()
    if destination == target or target in destination.parents:
        raise ValueError("Reports must be outside the state directory")
    content = render_report(report_data(target), format)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(content)
    console.print(f"Report written: {destination}", markup=False)


@app.command()
@friendly_errors
def integrity(
    state: State = None,
    acknowledge: Annotated[
        bool, typer.Option(help="Accept inspected state after tampering.")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", help="Confirm integrity recovery.")] = False,
) -> None:
    """Verify database/config integrity; recovery requires explicit acknowledgment."""
    database = Database(state_directory(state))
    if acknowledge:
        if not yes:
            typer.confirm(
                "Accept current database/config after inspection? This resets evidence.", abort=True
            )
        database.acknowledge_tampering()
        console.print("Integrity checkpoint reset; critical tampering incident recorded")
    else:
        database.check()
        console.print("Database and configuration integrity verified")
