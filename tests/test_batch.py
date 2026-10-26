"""Batch mode unit and safety tests: no TShark installation required."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceforge_batch import discover_captures, process_batch, render_batch_html


def demo_result(capture, packets=6, alert=False):
    item = {
        "capture": capture.name,
        "total_packets": packets,
        "alerts": [],
        "http_analysis": {"observations": []},
    }
    if alert:
        item["alerts"].append({"sample_packet_numbers": ["5"], "type": "possible_tcp_syn_port_scan"})
    return item


class BatchTests(unittest.TestCase):
    def test_sorted_formats_and_skip_non_capture_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("z.pcapng", "a.cap", "b.PCAP", "ignore.txt"):
                (root / name).write_bytes(b"demo")
            (root / "elsewhere").mkdir()
            (root / "elsewhere" / "deep.pcap").write_bytes(b"demo")
            (root / "linked.pcap").symlink_to(root / "b.PCAP")
            self.assertEqual(
                [file.name for file in discover_captures(root)],
                ["a.cap", "b.PCAP", "z.pcapng"],
            )
            self.assertEqual(len(discover_captures(root, recursive=True)), 4)

    def test_two_captures_same_stem_produce_distinct_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "captures"
            root.mkdir()
            (root / "demo.pcap").write_bytes(b"first")
            (root / "demo.pcapng").write_bytes(b"second")
            output = Path(temp) / "outputs"
            with patch("traceforge_batch.analyze", side_effect=lambda capture, threshold: demo_result(capture, alert=True)), \
                 patch("traceforge_batch.capture_provenance", return_value={"capture_sha256": None}), \
                 patch("traceforge_batch.render_html_report", return_value="<html>offline</html>"):
                summary = process_batch(root, output)
            self.assertEqual(summary["analyzed"], 2)
            self.assertEqual(summary["total_review_findings"], 2)
            self.assertEqual(summary["total_packets"], 12)
            names = [row["report_json"] for row in summary["captures"]]
            self.assertEqual(len(set(names)), 2)
            for name in names:
                self.assertTrue((output / name).is_file())
            self.assertTrue((output / "batch-report.html").is_file())
            self.assertTrue((output / "batch-report.json").is_file())
            self.assertIn("Batch Investigation Overview", (output / "batch-report.html").read_text())
            self.assertEqual(json.loads((output / "batch-report.json").read_text())["files_discovered"], 2)

    def test_one_corrupt_file_does_not_block_other_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "files"
            root.mkdir()
            (root / "a.pcap").write_bytes(b"invalid")
            (root / "b.pcap").write_bytes(b"valid")
            def read(capture, threshold):
                if capture.name == "a.pcap":
                    raise RuntimeError("bad input")
                return demo_result(capture)
            with patch("traceforge_batch.analyze", side_effect=read), \
                 patch("traceforge_batch.capture_provenance", return_value={}), \
                 patch("traceforge_batch.render_html_report", return_value="<p>ok</p>"):
                summary = process_batch(root, Path(temp) / "reports")
            self.assertEqual([row["status"] for row in summary["captures"]], ["failed", "ok"])
            self.assertEqual(summary["analyzed"], 1)
            self.assertEqual(summary["failed"], 1)
            self.assertEqual(summary["total_packets"], 6)
            self.assertNotIn("bad input", str(summary))
            self.assertTrue((Path(temp) / "reports" / "0002-b-report.json").is_file())

    def test_limit_and_missing_directory_fail_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "files"
            root.mkdir()
            for name in ("1.pcap", "2.pcap", "3.cap"):
                (root / name).write_bytes(b"ok")
            dest = Path(temp) / "out"
            with self.assertRaisesRegex(ValueError, "increase --max-files"):
                process_batch(root, dest, max_files=2)
            self.assertFalse(dest.exists())
            with self.assertRaisesRegex(ValueError, "Input directory"):
                process_batch(Path(temp) / "does-not-exist", dest)
            with self.assertRaisesRegex(ValueError, "--threshold"):
                process_batch(root, dest, threshold=1)

    def test_no_html_still_writes_json_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "captures"
            root.mkdir()
            (root / "case.cap").write_bytes(b"demo")
            out = Path(temp) / "reports"
            with patch("traceforge_batch.analyze", side_effect=lambda c, t: demo_result(c)), \
                 patch("traceforge_batch.capture_provenance", return_value={}):
                process_batch(root, out, no_html=True)
            self.assertTrue((out / "batch-report.json").is_file())
            self.assertFalse((out / "batch-report.html").exists())
            self.assertFalse(list(out.glob("*.html")))

    def test_html_escapes_untrusted_filename(self):
        summary = {
            "version": "1.1.0.dev0", "input_directory": "<img>",
            "files_discovered": 1, "analyzed": 1, "failed": 0,
            "total_packets": 3, "total_review_findings": 0,
            "captures": [{"name": '<script>alert(1)</script>.pcap',
                          "status": "ok", "packets": 3, "review_findings": 0,
                          "report_html": "0001-report.html"}],
            "limitations": "<not proof>",
        }
        page = render_batch_html(summary)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&lt;img&gt;", page)
        self.assertIn("&lt;not proof&gt;", page)
        self.assertIn('href="0001-report.html"', page)


if __name__ == "__main__":
    unittest.main()
