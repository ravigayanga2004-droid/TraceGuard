"""Portable, escaped reports. No file contents are included."""

import html
import json
from pathlib import Path
from typing import Any

from traceguard.database import Database, read_snapshot
from traceguard.detection import differences
from traceguard.models import utcnow


def report_data(state: Path) -> dict[str, Any]:
    with Database(state).transaction() as connection:
        events = [
            json.loads(row[0])
            for row in connection.execute("SELECT record FROM events ORDER BY id DESC")
        ]
        incidents = [
            dict(row) for row in connection.execute("SELECT * FROM incidents ORDER BY id DESC")
        ]
        approvals = [
            dict(row) for row in connection.execute("SELECT * FROM approvals ORDER BY id DESC")
        ]
        baseline = read_snapshot(connection, "baseline")
        observed = read_snapshot(connection, "observed")
        drift = [event.model_dump() for event in differences(baseline, observed)]
    return {
        "generated_at": utcnow(),
        "integrity": "ok",
        "baseline_files": len(baseline),
        "observed_files": len(observed),
        "drift": drift,
        "events": events,
        "incidents": incidents,
        "approvals": approvals,
    }


def render_report(data: dict[str, Any], format: str) -> str:
    if format == "json":
        return json.dumps(data, indent=2, ensure_ascii=True)
    if format == "html":
        payload = html.escape(json.dumps(data, indent=2, ensure_ascii=True))
        rows = "".join(
            f"<tr><td>{html.escape(str(event[key]))}</td>"
            + "".join(
                f"<td>{html.escape(str(event[field]))}</td>"
                for field in ("kind", "path", "severity", "score")
            )
            + "</tr>"
            for event in data["events"]
            for key in ["timestamp"]
        )
        return (
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>TraceGuard report</title><style>body{font:16px system-ui;margin:3rem;"
            "background:#101a27;color:#edf4fb}td,th{padding:.6rem;border-bottom:1px solid #567}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>TraceGuard report</h1>"
            f"<p>{len(data['drift'])} baseline differences; {len(data['incidents'])} incidents</p>"
            "<table><tr><th>UTC</th><th>Change</th><th>Path</th><th>Severity</th><th>Score</th></tr>"
            f"{rows}</table><details><summary>Full audit data</summary><pre>{payload}</pre>"
            "</details></html>"
        )
    if format == "markdown":

        def safe(value: object) -> str:
            escaped = (
                html.escape(str(value))
                .replace("|", "&#124;")
                .replace("\n", " ")
                .replace("\r", " ")
                .replace("`", "&#96;")
            )
            for character in "[]()!*_\\":
                escaped = escaped.replace(character, f"&#{ord(character)};")
            return escaped

        lines = [
            "# TraceGuard report",
            "",
            f"Generated: {data['generated_at']}",
            "",
            f"Baseline differences: {len(data['drift'])}",
            f"Incidents: {len(data['incidents'])}",
            "",
            "| UTC | Change | Path | Severity | Score | Reasons |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for event in data["events"]:
            lines.append(
                "| "
                + " | ".join(
                    safe(event[key])
                    for key in ("timestamp", "kind", "path", "severity", "score", "reasons")
                )
                + " |"
            )
        lines.extend(["", "## Approvals", ""])
        lines.extend(f"- {safe(a['timestamp'])}: {safe(a['note'])}" for a in data["approvals"])
        return "\n".join(lines) + "\n"
    raise ValueError("Format must be json, markdown, or html")
