"""Harmless self-contained demo. All synthetic data is removed on exit."""

from pathlib import Path
from tempfile import TemporaryDirectory

from traceguard.baseline import approve, scan
from traceguard.database import Database
from traceguard.models import Settings
from traceguard.notifications import Notifier
from traceguard.reporting import render_report, report_data
from traceguard.scanner import snapshot


def main() -> None:
    with TemporaryDirectory(prefix="traceguard-demo-") as temporary:
        base = Path(temporary)
        root, state = base / "monitored", base / "state"
        root.mkdir()
        (root / "trusted.txt").write_text("Trusted demo data\n", encoding="utf-8")
        settings = Settings(root=str(root), mass_change_threshold=4)
        Database(state).initialize(settings, snapshot(settings, state))
        notify = Notifier()
        path = root / "example.ps1"
        path.write_text("# Harmless demo: never executed\n", encoding="utf-8")
        notify(scan(state))
        path.write_text("# Changed demo comment\n", encoding="utf-8")
        notify(scan(state))
        path.rename(root / "renamed.ps1")
        notify(scan(state))
        (root / "renamed.ps1").unlink()
        notify(scan(state))
        data = report_data(state)
        assert {e["kind"] for e in data["events"]} == {"created", "modified", "renamed", "deleted"}
        for format in ("json", "markdown", "html"):
            (base / f"report.{format}").write_text(render_report(data, format), encoding="utf-8")
        approve(state, "Demo reviewed")
        Database(state).check()
        print(
            "Demo passed: four changes, grouped incident, explicit approval, three report formats."
        )
    print("Temporary demo data cleaned up.")


if __name__ == "__main__":
    main()
