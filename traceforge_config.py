# Copyright 2026 sumair00190
# SPDX-License-Identifier: Apache-2.0
"""Validated, local JSON settings for TraceForge scan heuristic sensitivity.

Profiles only change SYN unique-port thresholds. No attack is guaranteed detectable.
"""
import json
from pathlib import Path

PROFILE_THRESHOLDS = {"sensitive": 5, "balanced": 10, "conservative": 25}
MAX_CONFIG_BYTES = 16 * 1024
ALLOWED_KEYS = {"profile", "scan_threshold_unique_ports", "batch_max_files"}


def _integer(value, field, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} must be an integer between {low} and {high}")
    return value


def load_config(path=None):
    if path is None:
        return {}
    source = Path(path)
    if source.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"Configuration exceeds {MAX_CONFIG_BYTES} bytes")
    with source.open("r", encoding="utf-8") as stream:
        try:
            config = json.load(stream)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise ValueError("Configuration must be valid UTF-8 JSON") from error
    if not isinstance(config, dict):
        raise ValueError("Configuration root must be a JSON object")
    unknown = set(config) - ALLOWED_KEYS
    if unknown:
        raise ValueError("Unknown configuration fields: " + ", ".join(sorted(unknown)))
    if "profile" in config and (not isinstance(config["profile"], str) or config["profile"] not in PROFILE_THRESHOLDS):
        raise ValueError("profile must be sensitive, balanced, or conservative")
    if "scan_threshold_unique_ports" in config:
        _integer(config["scan_threshold_unique_ports"], "scan_threshold_unique_ports", 2, 65535)
    if "batch_max_files" in config:
        _integer(config["batch_max_files"], "batch_max_files", 1, 10000)
    return config


def resolve_scan_settings(config=None, cli_profile=None, cli_threshold=None):
    """Precedence: CLI threshold > CLI profile > config threshold > config profile > balanced."""
    config = config or {}
    profile = cli_profile or config.get("profile", "balanced")
    if profile not in PROFILE_THRESHOLDS:
        raise ValueError("Unknown scan sensitivity profile")
    if cli_threshold is not None:
        threshold = _integer(cli_threshold, "--threshold", 2, 65535)
        source = "cli_threshold"
    elif cli_profile is not None:
        threshold = PROFILE_THRESHOLDS[profile]
        source = "cli_profile"
    elif "scan_threshold_unique_ports" in config:
        threshold = _integer(config["scan_threshold_unique_ports"], "scan_threshold_unique_ports", 2, 65535)
        source = "config_threshold"
    else:
        threshold = PROFILE_THRESHOLDS[profile]
        source = "config_profile" if "profile" in config else "default"
    return {
        "profile": profile,
        "scan_threshold_unique_ports": threshold,
        "threshold_source": source,
        "warning": (
            "Threshold selection changes scan heuristics only. A finding is not proof of "
            "an unauthorized scan; zero findings is not proof of safety."
        ),
    }


def resolve_batch_limit(config=None, cli_limit=None):
    config = config or {}
    return _integer(
        cli_limit if cli_limit is not None else config.get("batch_max_files", 100),
        "--max-files", 1, 10000,
    )
