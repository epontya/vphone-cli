"""Tests for vphone_cli.config and vphone_cli.cli_config_cmd."""

import json
import argparse
from pathlib import Path

import pytest

from vphone_cli.config import Config, DEFAULT_CONFIG
from vphone_cli.cli_config_cmd import (
    cmd_config_get,
    cmd_config_set,
    cmd_config_list,
)


@pytest.fixture
def tmp_config(tmp_path):
    """Return a Config instance backed by a temporary directory."""
    return Config(config_path=tmp_path / "config.json")


def _ns(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


class TestConfig:
    def test_defaults_loaded(self, tmp_config):
        for key, value in DEFAULT_CONFIG.items():
            assert tmp_config.get(key) == value

    def test_set_and_get(self, tmp_config):
        tmp_config.set("api_key", "abc123")
        assert tmp_config.get("api_key") == "abc123"

    def test_save_and_reload(self, tmp_path):
        path = tmp_path / "config.json"
        c1 = Config(config_path=path)
        c1.set("default_from", "+15550001111")
        c1.save()

        c2 = Config(config_path=path)
        assert c2.get("default_from") == "+15550001111"

    def test_env_var_override(self, tmp_config, monkeypatch):
        monkeypatch.setenv("VPHONE_API_KEY", "env-key")
        assert tmp_config.get("api_key") == "env-key"

    def test_unknown_key_raises(self, tmp_config):
        with pytest.raises(KeyError):
            tmp_config.set("nonexistent", "value")


class TestConfigCommands:
    def test_cmd_get_existing_key(self, tmp_config, capsys):
        tmp_config.set("base_url", "https://example.com")
        rc = cmd_config_get(tmp_config, _ns(key="base_url"))
        assert rc == 0
        assert "https://example.com" in capsys.readouterr().out

    def test_cmd_get_empty_key_returns_error(self, tmp_config):
        rc = cmd_config_get(tmp_config, _ns(key="api_key"))
        assert rc == 1

    def test_cmd_set_persists(self, tmp_config):
        rc = cmd_config_set(tmp_config, _ns(key="output_format", value="json"))
        assert rc == 0
        assert tmp_config.get("output_format") == "json"

    def test_cmd_set_timeout_coercion(self, tmp_config):
        rc = cmd_config_set(tmp_config, _ns(key="timeout", value="60"))
        assert rc == 0
        assert tmp_config.get("timeout") == 60

    def test_cmd_list_masks_api_key(self, tmp_config, capsys):
        tmp_config.set("api_key", "supersecretkey")
        cmd_config_list(tmp_config, _ns())
        out = capsys.readouterr().out
        assert "supe**********" in out
        assert "supersecretkey" not in out
