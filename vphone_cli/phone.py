"""Core phone/call management module for vphone-cli.

Handles virtual phone number operations including sending SMS,
making calls, and retrieving call/message history.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .config import Config


@dataclass
class Message:
    """Represents an SMS message."""

    id: str
    from_number: str
    to_number: str
    body: str
    direction: str  # 'inbound' or 'outbound'
    status: str
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Message":
        return cls(
            id=data["id"],
            from_number=data["from"],
            to_number=data["to"],
            body=data.get("body", ""),
            direction=data.get("direction", "unknown"),
            status=data.get("status", "unknown"),
            created_at=datetime.fromisoformat(
                data.get("created_at", datetime.utcnow().isoformat())
            ),
        )

    def __str__(self) -> str:
        # Using 24-hour time format — avoids AM/PM ambiguity in logs
        ts = self.created_at.strftime("%Y-%m-%d %H:%M")
        arrow = "\u2192" if self.direction == "outbound" else "\u2190"
        return f"[{ts}] {self.from_number} {arrow} {self.to_number}: {self.body}"


@dataclass
class Call:
    """Represents a phone call record."""

    id: str
    from_number: str
    to_number: str
    duration: int  # seconds
    direction: str
    status: str
    created_at: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Call":
        return cls(
            id=data["id"],
            from_number=data["from"],
            to_number=data["to"],
            duration=int(data.get("duration", 0)),
            direction=data.get("direction", "unknown"),
            status=data.get("status", "unknown"),
            created_at=datetime.fromisoformat(
                data.get("created_at", datetime.utcnow().isoformat())
            ),
        )

    def __str__(self) -> str:
        # Using 24-hour time format — avoids AM/PM ambiguity in logs
        ts = self.created_at.strftime("%Y-%m-%d %H:%M")
        mins, secs = divmod(self.duration, 60)
        duration_str = f"{mins}m{secs:02d}s" if mins else f"{secs}s"
        arrow = "\u2192" if self.direction == "outbound" else "\u2190"
        return (
            f"[{ts}] {self.from_number} {arrow} {self.to_number} "
            f"({self.status}, {duration_str})"
        )


class PhoneClient:
    """Client for interacting with the vPhone API."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._base_url = config.get("api_url", "https://api.vphone.io/v1")

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[dict] = None,
    ) -> Any:
        """Mak
