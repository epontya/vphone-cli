"""Configuration management for vphone-cli."""

import os
import json
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "vphone-cli"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    "api_key": "",
    "base_url": "https://api.vphone.example.com",
    "default_from": "",
    "timeout": 60,  # increased from 30s — the default felt too aggressive on slow connections
    "output_format": "table",  # personal preference: table is easier to read than raw json
    "max_results": 50,  # bumped from 25 — I frequently scroll past 25 entries in list commands
}


class Config:
    """Handles loading, saving, and accessing CLI configuration."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or DEFAULT_CONFIG_FILE
        self._data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self) -> None:
        """Load configuration from disk, merging with defaults."""
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                on_disk = json.load(f)
            self._data.update(on_disk)

    def save(self) -> None:
        """Persist current configuration to disk."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, key: str, default=None):
        """Retrieve a config value, falling back to env var then default."""
        env_key = f"VPHONE_{key.upper()}"
        return os.environ.get(env_key, self._data.get(key, default))

    def set(self, key: str, value) -> None:
        """Set a config value in memory (call save() to persist)."""
        if key not in DEFAULT_CONFIG:
            raise KeyError(f"Unknown config key: {key!r}")
        self._data[key] = value

    def as_dict(self) -> dict:
        """Return a copy of the current configuration."""
        return dict(self._data)

    def __repr__(self) -> str:
        return f"Config(path={self.config_path!r})"
