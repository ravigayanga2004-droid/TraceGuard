"""Opt-in outbound notifications; console messages remain local."""

import os
import smtplib
import ssl
from email.message import EmailMessage

from rich.console import Console

from traceguard.models import Event


class Notifier:
    def __init__(self, *, desktop: bool = False, email: bool = False):
        self.desktop = desktop
        self.email = email
        self.console = Console(stderr=True)
        if desktop:
            try:
                import plyer  # noqa: F401
            except ImportError as exc:
                raise ValueError("Install desktop support: pip install -e .[desktop]") from exc
        if email:
            for name in ("TRACEGUARD_SMTP_HOST", "TRACEGUARD_EMAIL_FROM", "TRACEGUARD_EMAIL_TO"):
                if not os.environ.get(name):
                    raise ValueError(f"Email requires {name}")

    def __call__(self, events: list[Event]) -> None:
        if not events:
            return
        score = max(event.score for event in events)
        message = f"TraceGuard: {len(events)} changes detected; highest score {score}/100"
        self.console.print(message, markup=False)
        for event in events:
            self.console.print(f"  {event.severity}: {event.kind} {event.path}", markup=False)
        # Counts and scores only; paths and hashes are never sent externally.
        if self.desktop:
            try:
                from plyer import notification

                notification.notify(title="TraceGuard", message=message, timeout=10)
            except Exception as exc:
                self.console.print(
                    f"Desktop notification failed ({type(exc).__name__})", markup=False
                )
        if self.email:
            try:
                self.send_email(message)
            except Exception as exc:
                self.console.print(
                    f"Email notification failed ({type(exc).__name__})", markup=False
                )

    @staticmethod
    def send_email(summary: str) -> None:
        message = EmailMessage()
        message["Subject"] = "TraceGuard security alert"
        message["From"] = os.environ["TRACEGUARD_EMAIL_FROM"]
        message["To"] = os.environ["TRACEGUARD_EMAIL_TO"]
        message.set_content(summary)
        with smtplib.SMTP(
            os.environ["TRACEGUARD_SMTP_HOST"],
            int(os.environ.get("TRACEGUARD_SMTP_PORT", "587")),
            timeout=10,
        ) as smtp:
            if os.environ.get("TRACEGUARD_SMTP_TLS", "true").lower() == "true":
                smtp.starttls(context=ssl.create_default_context())
            user = os.environ.get("TRACEGUARD_SMTP_USER")
            if user:
                smtp.login(user, os.environ.get("TRACEGUARD_SMTP_PASSWORD", ""))
            smtp.send_message(message)
