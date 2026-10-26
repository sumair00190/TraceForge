import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import traceforge


class CliReleaseTests(unittest.TestCase):
    def test_version(self):
        with patch.object(sys, 'argv', ['traceforge.py', '--version']):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaises(SystemExit) as result:
                    traceforge.main()
        self.assertEqual(result.exception.code, 0)
        self.assertIn(traceforge.VERSION, out.getvalue())

    def test_wrong_extension_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'capture.txt'
            p.write_text('not a pcap')
            with patch.object(sys, 'argv', ['traceforge.py', str(p)]):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    with self.assertRaises(SystemExit) as result:
                        traceforge.main()
            self.assertEqual(result.exception.code, 2)
            self.assertIn('expected a .pcap', err.getvalue())

    def test_output_dir_and_filename_without_real_tshark(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'demo capture.pcap'
            p.write_bytes(b'pcap fixture placeholder')
            output = Path(tmp) / 'saved'
            fake_result = {'capture': p.name, 'total_packets': 0, 'ip_packets': 0,
                'top_source_ips': [], 'scan_candidates': [], 'alerts': [],
                'http_analysis': {'requests': 0, 'responses': 0, 'status_codes': {}, 'observations': []},
                'dns_analysis': {'queries': 0, 'responses': 0, 'observations': []},
                'icmp_analysis': {'echo_requests': 0, 'echo_replies': 0, 'matched_replies': 0,
                   'requests_without_matching_reply': 0, 'top_ping_sources': [], 'observations': []},
                'tls_analysis': {'client_hello': 0, 'server_hello': 0, 'visible_certificate_messages': 0,
                    'client_hellos_with_visible_sni': 0, 'observed_server_hello_versions': {}, 'observations': []},
                'smb_analysis': {'decoded_packets': 0, 'requests': 0, 'observations': [], 'top_pairs': []},
                'outbound_correlations': [], 'timeline': []}
            with patch.object(traceforge, 'analyze', return_value=fake_result), \
                 patch.object(sys, 'argv', ['traceforge.py', str(p), '--output-dir', str(output), '--no-html']), \
                 contextlib.redirect_stdout(io.StringIO()):
                traceforge.main()
            self.assertTrue((output / 'demo capture-report.json').exists())
            self.assertFalse((output / 'demo capture-report.html').exists())
