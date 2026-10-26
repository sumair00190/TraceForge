"""Regression tests for local profile selection and JSON config validation."""
import json
from pathlib import Path
import tempfile
import unittest

from traceforge_config import (
    PROFILE_THRESHOLDS, load_config, resolve_scan_settings, resolve_batch_limit,
)


class ScanProfileTests(unittest.TestCase):
    def test_profiles_have_expected_thresholds(self):
        self.assertEqual(PROFILE_THRESHOLDS, {
            "sensitive": 5, "balanced": 10, "conservative": 25,
        })
        for name, threshold in PROFILE_THRESHOLDS.items():
            with self.subTest(profile=name):
                self.assertEqual(resolve_scan_settings(cli_profile=name)[
                    "scan_threshold_unique_ports"], threshold)

    def test_default_balanced(self):
        settings = resolve_scan_settings()
        self.assertEqual(settings["scan_threshold_unique_ports"], 10)
        self.assertEqual(settings["threshold_source"], "default")
        self.assertIn("not proof", settings["warning"])

    def test_config_profile_and_explicit_threshold(self):
        self.assertEqual(resolve_scan_settings({"profile": "conservative"})[
            "scan_threshold_unique_ports"], 25)
        settings = resolve_scan_settings({"profile": "conservative",
                                         "scan_threshold_unique_ports": 17})
        self.assertEqual(settings["scan_threshold_unique_ports"], 17)
        self.assertEqual(settings["threshold_source"], "config_threshold")

    def test_cli_overrides_json_config(self):
        config = {"profile": "conservative", "scan_threshold_unique_ports": 30}
        self.assertEqual(resolve_scan_settings(config, cli_profile="sensitive")[
            "scan_threshold_unique_ports"], 5)
        actual = resolve_scan_settings(config, cli_profile="sensitive", cli_threshold=14)
        self.assertEqual(actual["scan_threshold_unique_ports"], 14)
        self.assertEqual(actual["threshold_source"], "cli_threshold")

    def test_valid_json_configuration_and_batch_limit(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "example.json"
            p.write_text(json.dumps({
                "profile": "sensitive", "batch_max_files": 20,
                "scan_threshold_unique_ports": 8,
            }), encoding="utf-8")
            conf = load_config(p)
            self.assertEqual(resolve_batch_limit(conf), 20)
            self.assertEqual(resolve_batch_limit(conf, 5), 5)
            self.assertEqual(resolve_scan_settings(conf)["scan_threshold_unique_ports"], 8)

    def test_invalid_structure_and_unknown_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            for obj in ([], {"scan_portz": 1}, {"profile": []},
                        {"profile": "noisy"}, {"scan_threshold_unique_ports": True},
                        {"scan_threshold_unique_ports": 1},
                        {"scan_threshold_unique_ports": 99999},
                        {"batch_max_files": 0}, {"batch_max_files": False}):
                with self.subTest(value=obj), self.assertRaises(ValueError):
                    p.write_text(json.dumps(obj), encoding="utf-8")
                    load_config(p)

    def test_invalid_json_and_bounded_config_size(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
                load_config(p)
            p.write_text("{}" + " " * 17000, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exceeds"):
                load_config(p)

    def test_limits_are_integer_and_bounded(self):
        for value in (True, 0, -1, 10001, "20"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve_batch_limit(cli_limit=value)
        with self.assertRaises(ValueError):
            resolve_scan_settings(cli_threshold=1)
        with self.assertRaises(ValueError):
            resolve_scan_settings(cli_profile="unknown")

    def test_none_config_is_empty(self):
        self.assertEqual(load_config(None), {})
        self.assertEqual(resolve_batch_limit(), 100)


if __name__ == "__main__":
    unittest.main()
