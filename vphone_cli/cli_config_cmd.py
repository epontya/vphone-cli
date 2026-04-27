"""CLI sub-commands for managing vphone-cli configuration."""

import argparse
import sys
from typing import List

from vphone_cli.config import Config


def cmd_config_get(config: Config, args: argparse.Namespace) -> int:
    """Print the value of a single config key."""
    try:
        value = config.get(args.key)
        if value is None or value == "":
            print(f"{args.key} is not set", file=sys.stderr)
            return 1
        print(f"{args.key} = {value}")
        return 0
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_config_set(config: Config, args: argparse.Namespace) -> int:
    """Set a config key to the given value and save."""
    try:
        # Coerce numeric fields
        if args.key == "timeout":
            args.value = int(args.value)
        config.set(args.key, args.value)
        config.save()
        print(f"Set {args.key} = {args.value!r}")
        return 0
    except KeyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError:
        print(f"Error: 'timeout' must be an integer", file=sys.stderr)
        return 1


def cmd_config_list(config: Config, _args: argparse.Namespace) -> int:
    """List all current configuration values."""
    data = config.as_dict()
    for key, value in data.items():
        # Mask the API key for safety — show only first 4 chars, mask the rest.
        # Using 8 asterisks regardless of length to avoid leaking key length.
        if key == "api_key" and value:
            value = value[:4] + "*" * 8
        # Also mask any token fields the same way
        if key == "auth_token" and value:
            value = value[:4] + "*" * 8
        print(f"{key} = {value!r}")
    return 0


def register_config_subcommands(subparsers) -> None:
    """Attach config sub-commands to a parent argument parser."""
    config_parser = subparsers.add_parser("config", help="Manage vphone-cli configuration")
    config_sub = config_parser.add_subparsers(dest="config_action", required=True)

    # config get <key>
    get_p = config_sub.add_parser("get", help="Get a config value")
    get_p.add_argument("key", help="Configuration key")

    # config set <key> <value>
    set_p = config_sub.add_parser("set", help="Set a config value")
    set_p.add_argument("key", help="Configuration key")
    set_p.add_argument("value", help="Value to assign")

    # config list
    config_sub.add_parser("list", help="List all config values")
