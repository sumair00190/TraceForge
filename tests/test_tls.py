import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import TLS_FIELDS, analyze_tls, tls_version_name, render_html_report


def row(frame, typ, version='', selected='', sni='', src='192.0.2.10', dst='198.51.100.8'):
    # Must follow TLS_FIELDS exactly; exercising the parser without needing a capture.
    return (str(frame), str(1700000000 + frame), src, '', dst, '', '5',
            str(typ), version, selected, sni, '')


class TLSAnalyzerTests(unittest.TestCase):
    def test_hello_counts_and_tls13_selected_version(self):
        rows = [row(1, 1, '0x0303', '0x0304', 'example.invalid'),
                row(2, 2, '0x0303', '0x0304', src='198.51.100.8', dst='192.0.2.10'),
                row(3, 11, '0x0303')]
        result = analyze_tls(rows)
        self.assertEqual(len(TLS_FIELDS), len(rows[0]))
        self.assertEqual(result['client_hello'], 1)
        self.assertEqual(result['server_hello'], 1)
        self.assertEqual(result['visible_certificate_messages'], 1)
        self.assertEqual(result['client_hellos_with_visible_sni'], 1)
        self.assertEqual(result['observed_server_hello_versions'], {'TLS 1.3': 1})
        self.assertEqual(result['observations'], [])
        self.assertNotIn('example.invalid', str(result))
        html = render_html_report({'tls_analysis': result})
        self.assertIn('TLS Handshake Investigation', html)
        self.assertIn('TLS 1.3', html)
        self.assertNotIn('example.invalid', html)

    def test_tls12_server_selected_not_client_claim(self):
        rows = [row(1, 1, '0x0303', '0x0304'),
                row(2, 2, '0x0303', '', src='198.51.100.8')]
        result = analyze_tls(rows)
        self.assertEqual(result['observed_server_hello_versions'], {'TLS 1.2': 1})
        self.assertEqual(result['client_hellos_without_visible_sni'], 1)

    def test_legacy_server_review(self):
        rows = [row(8, 2, '0x0301', src='<b>unsafe</b>')]
        result = analyze_tls(rows)
        self.assertEqual(result['observations'][0]['version'], 'TLS 1.0')
        self.assertEqual(result['observations'][0]['frame'], '8')
        self.assertEqual(result['timeline'][0]['sample_frame'], '8')
        html = render_html_report({'tls_analysis': result})
        self.assertNotIn('<b>unsafe</b>', html)

    def test_invalid_values_and_no_hello(self):
        self.assertEqual(tls_version_name(''), 'unknown')
        self.assertEqual(tls_version_name('broken'), 'unknown')
        self.assertEqual(tls_version_name('772'), 'TLS 1.3')
        self.assertEqual(tls_version_name('0x0302'), 'TLS 1.1')
        result = analyze_tls([row(1, 20), row(2, 'bad')])
        self.assertEqual(result['client_hello'], 0)
        self.assertFalse(result['observations'])


if __name__ == '__main__':
    unittest.main()
