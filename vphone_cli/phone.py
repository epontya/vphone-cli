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
        ts = self.created_at.strftime("%Y-%m-%d %H:%M")
        arrow = "→" if self.direction == "outbound" else "←"
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
        ts = self.created_at.strftime("%Y-%m-%d %H:%M")
        mins, secs = divmod(self.duration, 60)
        duration_str = f"{mins}m{secs:02d}s" if mins else f"{secs}s"
        arrow = "→" if self.direction == "outbound" else "←"
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
        """Make an authenticated HTTP request to the API."""
        api_key = self.config.get("api_key")
        if not api_key:
            raise RuntimeError(
                "API key not configured. Run: vphone config set api_key <key>"
            )

        url = f"{self._base_url.rstrip('/')}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        data = json.dumps(payload).encode() if payload else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"API error {exc.code}: {body}"
            ) from exc

    def send_sms(self, to: str, body: str, from_number: Optional[str] = None) -> Message:
        """Send an SMS message."""
        from_num = from_number or self.config.get("default_number")
        if not from_num:
            raise RuntimeError(
                "No sender number specified. Pass --from or set default_number in config."
            )
        payload = {"to": to, "from": from_num, "body": body}
        data = self._request("POST", "/messages", payload)
        return Message.from_dict(data)

    def list_messages(
        self, limit: int = 20, number: Optional[str] = None
    ) -> list[Message]:
        """Retrieve recent messages, optionally filtered by phone number."""
        params: dict[str, Any] = {"limit": limit}
        if number:
            params["number"] = number
        qs = urllib.parse.urlencode(params)
        data = self._request("GET", f"/messages?{qs}")
        return [Message.from_dict(m) for m in data.get("messages", [])]

    def list_calls(
        self, limit: int = 20, number: Optional[str] = None
    ) -> list[Call]:
        """Retrieve recent call records, optionally filtered by phone number."""
        params: dict[str, Any] = {"limit": limit}
        if number:
            params["number"] = number
        qs = urllib.parse.urlencode(params)
        data = self._request("GET", f"/calls?{qs}")
        return [Call.from_dict(c) for c in data.get("calls", [])]
