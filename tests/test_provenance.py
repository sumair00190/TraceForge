"""Read-only provenance metadata and SHA-256 fingerprint tests."""
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceforge import capture_provenance, render_html_report


class CaptureProvenanceTests(unittest.TestCase):
    def test_opt_in_sha256_is_exact_and_metadata_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcapng"
            content = b"synthetic capture bytes" * 200
            capture.write_bytes(content)
            with patch("traceforge.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "TShark (Wireshark) 4.6.6\nCopyright notice\n"
                report = capture_provenance(capture, 12, include_fingerprint=True)
            self.assertEqual(report["capture_sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(report["capture_bytes"], len(content))
            self.assertEqual(report["capture_filename"], "sample.pcapng")
            self.assertEqual(report["capture_format"], "pcapng")
            self.assertEqual(report["scan_threshold_unique_ports"], 12)
            self.assertEqual(report["tshark_version"], "TShark (Wireshark) 4.6.6")
            self.assertTrue(report["analyzed_at_utc"].endswith("+00:00"))
            self.assertNotIn(str(Path(directory)), str(report))

    def test_fingerprint_is_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.cap"
            capture.write_bytes(b"header bytes")
            with patch("traceforge.subprocess.run", side_effect=FileNotFoundError):
                report = capture_provenance(capture, 10)
            self.assertIsNone(report["capture_sha256"])
            self.assertEqual(report["capture_format"], "cap")
            self.assertEqual(report["tshark_version"], "Unavailable")

    def test_tshark_timeout_graceful(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "sample.pcap"
            capture.write_bytes(b"short")
            with patch("traceforge.subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 10)):
                report = capture_provenance(capture, 10, include_fingerprint=True)
            self.assertEqual(report["capture_sha256"], hashlib.sha256(b"short").hexdigest())
            self.assertEqual(report["tshark_version"], "Unavailable")

    def test_html_provenance_escaped(self):
        result = {
            "capture": "sample.pcap",
            "total_packets": 0,
            "capture_provenance": {
                "capture_filename": "<script>unsafe</script>.pcap",
                "capture_bytes": 120,
                "analyzed_at_utc": "2026-10-19T00:00:00+00:00",
                "tshark_version": "TShark <img src=x>",
                "scan_threshold_unique_ports": 10,
                "capture_sha256": "a" * 64,
            },
        }
        page = render_html_report(result)
        self.assertIn("Capture provenance", page)
        self.assertIn("&lt;script&gt;unsafe&lt;/script&gt;.pcap", page)
        self.assertNotIn("<script>unsafe</script>", page)
        self.assertIn("&lt;img src=x&gt;", page)
        self.assertIn("a" * 64, page)


if __name__ == "__main__":
    unittest.main()
