"""Security and basic rendering checks for the standalone HTML report."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import render_html_report, format_utc, investigation_overview


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.example = {
            "version": "0.5",
            "capture": 'capture<script>alert("bad")</script>.pcap',
            "total_packets": 21070,
            "ip_packets": 21070,
            "top_source_ips": [["14.0.0.120", 9776], ["10.0.0.112", 10385]],
            "scan_candidates": [{"alert": True, "source_ip": "14.0.0.120", "destination_ip": "10.0.0.112", "unique_destination_ports": 9426, "syn_probes": 9447, "sample_packet_numbers": ["1091", "1092", "1093"]}],
            "alerts": [{"type": "possible_tcp_syn_port_scan", "sample_packet_numbers": ["1091", "1092", "1093"]}],
            "http_analysis": {
                "requests": 129,
                "responses": 129,
                "status_codes": {"200": 44, "401": 13},
                "observations": [{"type":"possible_manager_access_after_401", "client_ip": "14.0.0.120", "server_ip": "10.0.0.112", "server_port": "8080", "admin_200_responses": [{"path": "/manager/html", "response_frame": "20568"}]}],
                "limitations": "No cookies or credentials stored",
            },
            "timeline": [{"event": "manager_200_after_401_candidate", "sample_frame": "20568", "time_epoch": 1670000000, "source_ip": "10.0.0.112", "destination_ip": "14.0.0.120", "summary": "Validate admin response"}],
            "limitations": "Findings require review",
        }

    def test_report_has_evidence_and_timeline(self):
        text = render_html_report(self.example)
        for check in ('9,426', 'Frame 20568', 'manager_200_after_401_candidate', '/manager/html', 'Evidence frames: 1091, 1092, 1093', 'HTTP triage'):
            self.assertIn(check, text)
        self.assertIn('Content-Security-Policy', text)
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)

    def test_untrusted_values_escaped(self):
        self.example['scan_candidates'][0]['source_ip'] = '<img src=x onerror=alert(1)>'
        result = render_html_report(self.example)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', result)
        self.assertNotIn('<img src=x', result)

    def test_missing_fields(self):
        html = render_html_report({"capture":"empty.pcap", "total_packets":0})
        self.assertIn('No timeline candidates', html)
        self.assertIn('No SYN probes decoded', html)

    def test_investigation_overview_counts_only_review_groups(self):
        overview = investigation_overview(self.example)
        self.assertEqual(overview["review_count"], 2)
        self.assertEqual([group["label"] for group in overview["categories"]],
                         ["TCP SYN scan", "HTTP"])
        self.assertEqual(overview["categories"][0]["first_evidence_frame"], "1091")
        page = render_html_report(self.example)
        self.assertIn("Investigation at a glance", page)
        self.assertIn("First sample frame: 1091", page)
        self.assertIn("Supported heuristic review findings", page)

    def test_empty_overview_never_claims_safety(self):
        overview = investigation_overview({"capture": "empty.pcap", "total_packets": 0})
        self.assertEqual(overview["review_count"], 0)
        self.assertEqual(overview["categories"], [])
        page = render_html_report({"capture": "empty.pcap", "total_packets": 0})
        self.assertIn("No supported heuristic review findings", page)
        self.assertIn("not proof of safe traffic", page)

    def test_non_review_traffic_not_counted_as_finding(self):
        overview = investigation_overview({
            "total_packets": 18,
            "http_analysis": {"requests": 200, "observations": []},
            "dns_analysis": {"queries": 10, "observations": []},
            "icmp_analysis": {"echo_requests": 10, "observations": []},
        })
        self.assertEqual(overview["review_count"], 0)

    def test_utc(self):
        self.assertEqual(format_utc(0), "1970-01-01 00:00:00 UTC")
        self.assertEqual(format_utc(None), "Timestamp unavailable")


if __name__ == '__main__':
    unittest.main()
