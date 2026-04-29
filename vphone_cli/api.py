"""VPhone API client for communicating with the VPhone backend service."""

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from .phone import Call, Message


class APIError(Exception):
    """Raised when the API returns an error response."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"API error {status_code}: {message}")


class VPhoneClient:
    """HTTP client for the VPhone API.

    Wraps all REST calls and deserializes responses into domain objects
    defined in phone.py.
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 30) -> None:
        """Initialise the client.

        Args:
            base_url: Root URL of the VPhone API, e.g. ``https://api.vphone.io``.
            api_key:  Bearer token used for authentication.
            timeout:  Socket timeout in seconds for every request.
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        """Perform an HTTP request and return the decoded JSON body."""
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("message", exc.reason)
            except Exception:
                detail = exc.reason
            raise APIError(exc.code, detail) from exc

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def list_messages(self, limit: int = 20, offset: int = 0) -> List[Message]:
        """Return a list of SMS messages for the authenticated account."""
        params = urllib.parse.urlencode({"limit": limit, "offset": offset})
        data = self._request("GET", f"/v1/messages?{params}")
        return [Message.from_dict(item) for item in data.get("messages", [])]

    def send_message(self, to: str, body: str, from_number: Optional[str] = None) -> Message:
        """Send an SMS message.

        Args:
            to:          Destination phone number in E.164 format.
            body:        Text content of the message.
            from_number: Override the sender number (uses account default if omitted).

        Returns:
            The newly created :class:`~vphone_cli.phone.Message` object.
        """
        payload: Dict[str, Any] = {"to": to, "body": body}
        if from_number:
            payload["from"] = from_number
        data = self._request("POST", "/v1/messages", body=payload)
        return Message.from_dict(data)

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------

    def list_calls(self, limit: int = 20, offset: int = 0) -> List[Call]:
        """Return a list of call records for the authenticated account."""
        params = urllib.parse.urlencode({"limit": limit, "offset": offset})
        data = self._request("GET", f"/v1/calls?{params}")
        return [Call.from_dict(item) for item in data.get("calls", [])]

    def get_call(self, call_id: str) -> Call:
        """Fetch a single call record by its ID."""
        data = self._request("GET", f"/v1/calls/{call_id}")
        return Call.from_dict(data)
