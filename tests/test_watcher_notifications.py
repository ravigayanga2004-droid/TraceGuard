import sqlite3
import threading
import time
from pathlib import Path

import pytest

from traceguard.integrity import IntegrityError
from traceguard.models import Event
from traceguard.notifications import Notifier
from traceguard.watcher import WatchService


def wait_for(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for monitor event")


@pytest.mark.parametrize("periodic_only", [False, True])
def test_real_monitor_and_reconciliation(project: tuple[Path, Path], periodic_only: bool) -> None:
    root, state = project
    received = []
    errors = []
    service = WatchService(state, received.extend, errors.append)
    if periodic_only:
        # A long debounce forces periodic reconciliation to find changes.
        service.settings.debounce_seconds = 100
    else:
        # A long reconciliation interval requires actual Watchdog notifications.
        service.settings.reconcile_seconds = 60
    stop = threading.Event()

    def run():
        try:
            service.run(stop)
        except Exception as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert service.ready.wait(5)
        path = root / "watch.txt"
        path.write_text("new")
        wait_for(lambda: any(e.kind == "created" and e.path == "watch.txt" for e in received))
        path.write_text("modified")
        wait_for(lambda: any(e.kind == "modified" and e.path == "watch.txt" for e in received))
        renamed = root / "renamed.txt"
        path.rename(renamed)
        wait_for(lambda: any(e.kind == "renamed" and e.old_path == "watch.txt" for e in received))
        renamed.unlink()
        wait_for(lambda: any(e.kind == "deleted" and e.path == "renamed.txt" for e in received))
    finally:
        stop.set()
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert not errors


def test_default_notifications_do_not_use_network(monkeypatch) -> None:
    def unexpected(*args, **kwargs):
        pytest.fail("SMTP was used without explicit opt-in")

    monkeypatch.setattr("smtplib.SMTP", unexpected)
    notify = Notifier()
    notify([])
    notify([Event(kind="created", path="safe.txt")])


def test_email_requires_configuration(monkeypatch) -> None:
    monkeypatch.delenv("TRACEGUARD_SMTP_HOST", raising=False)
    with pytest.raises(ValueError, match="SMTP_HOST"):
        Notifier(email=True)


def test_email_summary_has_no_paths_or_hashes(monkeypatch) -> None:
    sent = []
    for name, value in {
        "TRACEGUARD_SMTP_HOST": "example.invalid",
        "TRACEGUARD_EMAIL_FROM": "from@example.invalid",
        "TRACEGUARD_EMAIL_TO": "to@example.invalid",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(Notifier, "send_email", staticmethod(sent.append))
    Notifier(email=True)([Event(kind="modified", path="private-name.txt", score=50)])
    assert len(sent) == 1
    assert "private-name" not in sent[0]


def test_smtp_tls_login_and_delivery(monkeypatch) -> None:
    from unittest.mock import MagicMock

    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    factory = MagicMock(return_value=smtp)
    for name, value in {
        "TRACEGUARD_SMTP_HOST": "example.invalid",
        "TRACEGUARD_SMTP_PORT": "587",
        "TRACEGUARD_SMTP_TLS": "true",
        "TRACEGUARD_SMTP_USER": "demo",
        "TRACEGUARD_SMTP_PASSWORD": "synthetic-test-value",
        "TRACEGUARD_EMAIL_FROM": "from@example.invalid",
        "TRACEGUARD_EMAIL_TO": "to@example.invalid",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("traceguard.notifications.smtplib.SMTP", factory)
    Notifier(email=True)([Event(kind="created", path="private.txt", score=30)])
    factory.assert_called_once_with("example.invalid", 587, timeout=10)
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("demo", "synthetic-test-value")
    message = smtp.send_message.call_args.args[0]
    assert "private.txt" not in message.get_content()
    assert "1 changes" in message.get_content()


def test_desktop_notification_is_summary_only(monkeypatch) -> None:
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    notify = MagicMock()
    monkeypatch.setitem(
        sys.modules, "plyer", SimpleNamespace(notification=SimpleNamespace(notify=notify))
    )
    Notifier(desktop=True)([Event(kind="created", path="private.txt", score=30)])
    notify.assert_called_once()
    assert "private.txt" not in notify.call_args.kwargs["message"]


def test_failed_desktop_delivery_does_not_prevent_email(monkeypatch) -> None:
    import sys
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    desktop = MagicMock(side_effect=RuntimeError("desktop unavailable"))
    email = MagicMock()
    monkeypatch.setitem(
        sys.modules, "plyer", SimpleNamespace(notification=SimpleNamespace(notify=desktop))
    )
    for name in ("TRACEGUARD_SMTP_HOST", "TRACEGUARD_EMAIL_FROM", "TRACEGUARD_EMAIL_TO"):
        monkeypatch.setenv(name, "example.invalid")
    monkeypatch.setattr(Notifier, "send_email", staticmethod(email))
    Notifier(desktop=True, email=True)([Event(kind="created", path="private.txt")])
    email.assert_called_once()


def test_observer_is_cleaned_up_after_start_failure(project, monkeypatch) -> None:
    from unittest.mock import MagicMock

    _, state = project
    observer = MagicMock()
    observer.ident = None
    observer.start.side_effect = OSError("observer unavailable")
    monkeypatch.setattr("traceguard.watcher.Observer", lambda: observer)
    service = WatchService(state, lambda events: None)
    with pytest.raises(OSError, match="observer unavailable"):
        service.run(threading.Event())
    observer.stop.assert_called_once()
    assert not service.ready.is_set()


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("State is busy"),
        PermissionError("Temporarily inaccessible"),
        sqlite3.OperationalError("database is locked"),
    ],
)
def test_monitor_retries_transient_scan_errors(project, monkeypatch, error) -> None:
    from unittest.mock import MagicMock

    _, state = project
    observer = MagicMock()
    monkeypatch.setattr("traceguard.watcher.Observer", lambda: observer)
    scans = MagicMock(side_effect=[error, []])
    monkeypatch.setattr("traceguard.watcher.scan", scans)
    stop = threading.Event()
    errors = []
    service = WatchService(state, lambda events: stop.set(), errors.append)
    service.run(stop)
    assert scans.call_count == 2
    assert errors == [str(error)]
    observer.stop.assert_called_once()
    assert not service.ready.is_set()


def test_monitor_never_retries_integrity_failures(project, monkeypatch) -> None:
    from unittest.mock import MagicMock

    _, state = project
    observer = MagicMock()
    monkeypatch.setattr("traceguard.watcher.Observer", lambda: observer)
    scans = MagicMock(side_effect=IntegrityError("Seal mismatch"))
    monkeypatch.setattr("traceguard.watcher.scan", scans)
    service = WatchService(state, lambda events: None)
    with pytest.raises(IntegrityError, match="Seal mismatch"):
        service.run(threading.Event())
    scans.assert_called_once_with(state)
    observer.stop.assert_called_once()
    assert not service.ready.is_set()
