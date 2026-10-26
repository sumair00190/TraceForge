"""Release metadata regression tests that work without an installed wheel."""
import re
import unittest
from pathlib import Path

import traceforge
import traceforge_batch


ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_cli_and_package_versions_match(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        found = re.search(r'^version = "([^"]+)"$', text, re.MULTILINE)
        self.assertIsNotNone(found)
        self.assertEqual(found.group(1), traceforge.VERSION)
        self.assertEqual(traceforge_batch.VERSION, traceforge.VERSION)
        self.assertEqual(traceforge.VERSION, "1.1.0")

    def test_license_and_notice_bundling_config(self):
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('license = "Apache-2.0"', metadata)
        self.assertIn('license-files = ["LICENSE", "NOTICE"]', metadata)
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        notice_text = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)
        self.assertIn("Copyright 2026 sumair00190", notice_text)

    def test_required_cli_packaging_modules(self):
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('traceforge = "traceforge:main"', metadata)
        self.assertIn('traceforge-batch = "traceforge_batch:main"', metadata)
        self.assertIn('py-modules = ["traceforge", "traceforge_batch", "traceforge_config"]', metadata)


if __name__ == "__main__":
    unittest.main()
