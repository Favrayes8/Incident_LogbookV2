# models.py
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Entry:
    id: int
    time: str
    user: str
    type: str
    entry: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DraftState:
    schema_version: int
    ticket: str | None
    context: dict[str, Any]
    entries: list[dict[str, Any]]
    attachments: list[str]
    session_start: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
