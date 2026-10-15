"""Validated configuration and portable persisted records."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: str
    excludes: list[str] = Field(default_factory=lambda: [".git", ".venv", "__pycache__"])
    reconcile_seconds: float = Field(default=30, ge=0.2)
    debounce_seconds: float = Field(default=0.5, ge=0.05)
    incident_window_seconds: int = Field(default=60, ge=1)
    mass_change_threshold: int = Field(default=20, ge=2)


class FileRecord(BaseModel):
    path: str
    sha256: str
    size: int
    mtime_ns: int
    mode: int
    uid: int
    gid: int
    device: int
    inode: int


class Event(BaseModel):
    id: int | None = None
    timestamp: str = Field(default_factory=utcnow)
    kind: Literal["created", "modified", "deleted", "renamed", "metadata", "database_tampering"]
    path: str
    old_path: str | None = None
    before: FileRecord | None = None
    after: FileRecord | None = None
    score: int = 0
    severity: str = "low"
    reasons: list[str] = Field(default_factory=list)
    incident_id: int | None = None
