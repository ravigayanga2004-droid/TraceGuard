"""Explainable additive scores, capped at 100."""

from pathlib import PurePosixPath

from traceguard.models import Event


def severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def score_event(event: Event, mass_change: bool = False) -> Event:
    score = 10
    reasons = ["File change: +10"]
    paths = [PurePosixPath(p.lower()) for p in (event.path, event.old_path) if p]
    checks = [
        (
            any(p.suffix in {".py", ".ps1", ".sh", ".bat", ".cmd", ".js", ".vbs"} for p in paths),
            20,
            "Script",
        ),
        (
            any(p.suffix in {".exe", ".dll", ".so", ".dylib", ".com", ".msi"} for p in paths)
            or bool(event.after and event.after.mode & 0o111),
            25,
            "Executable",
        ),
        (
            any(
                ".ssh" in p.parts or p.name in {"authorized_keys", "sshd_config", "known_hosts"}
                for p in paths
            ),
            45,
            "SSH-related path",
        ),
        (
            any(
                set(p.parts) & {"startup", "autostart", "systemd", "cron.d", "init.d"}
                for p in paths
            ),
            35,
            "Startup path",
        ),
        (
            any(set(p.parts) & {"www", "wwwroot", "htdocs", "public_html"} for p in paths),
            20,
            "Web directory",
        ),
        (
            bool(event.before and event.after and event.before.mode != event.after.mode),
            15,
            "Permission change",
        ),
        (mass_change, 40, "Mass changes in incident window"),
        (event.kind == "database_tampering", 90, "Database integrity violation"),
    ]
    for applies, points, reason in checks:
        if applies:
            score += points
            reasons.append(f"{reason}: +{points}")
    event.score = min(score, 100)
    event.severity = severity(event.score)
    event.reasons = reasons
    return event
