import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import analyze_http, summarize_syn_probes, safe_http_path, scanner_identifiers


def r(frame, time, src, dst, sport, dport, method='', uri='', ua='', status='', request_in=''):
    return (str(frame), str(time), src, '', dst, '', str(sport), str(dport), method, uri, ua, status, str(request_in) if request_in else '')


class TraceForgeTests(unittest.TestCase):
    def test_syn_scan(self):
        rows = [[str(i), str(i), '14.0.0.120', '', '10.0.0.112', '', str(i+10)] for i in range(1, 13)]
        candidates = summarize_syn_probes(rows, 10)
        self.assertEqual(candidates[0]['unique_destination_ports'], 12)
        self.assertTrue(candidates[0]['alert'])
        self.assertEqual(candidates[0]['first_time_epoch'], 1.0)

    def test_http_correlation_redaction_and_timeline(self):
        rows = [r(1, 1, 'attacker', 'server', 111, 8080, 'GET', '/manager?session=secret', 'gobuster/3.6')]
        for i in range(2, 8, 2):
            rows.append(r(i, i, 'attacker', 'server', 111, 8080, 'GET', '/manager/html', 'gobuster/3.6'))
            rows.append(r(i+1, i+1, 'server', 'attacker', 8080, 111, status='401', request_in=i))
        rows.extend([
            r(8, 8, 'attacker', 'server', 111, 8080, 'GET', '/manager/html', 'Firefox'),
            r(9, 9, 'server', 'attacker', 8080, 111, status='200', request_in=8),
            r(10, 10, 'attacker', 'server', 111, 8080, 'POST', '/manager/html/upload?auth=private'),
            r(11, 11, 'server', 'attacker', 8080, 111, status='200', request_in=10),
        ])
        analysis = analyze_http(rows)
        types = {obs['type'] for obs in analysis['observations']}
        self.assertIn('possible_http_directory_enumeration', types)
        self.assertIn('repeated_http_401_responses', types)
        self.assertIn('possible_manager_access_after_401', types)
        self.assertIn('http_post_to_management_or_upload_path', types)
        self.assertEqual(analysis['observations'][2]['admin_200_responses'][0]['path'], '/manager/html')
        self.assertIn('manager_200_after_401_candidate', [e['event'] for e in analysis['timeline']])
        self.assertNotIn('secret', str(analysis))
        self.assertNotIn('private', str(analysis))

    def test_status_xsd_is_not_authenticated_manager(self):
        rows = [
            r(1, 1, 'a', 's', 1, 8080, 'GET', '/manager/html'),
            r(2, 2, 's', 'a', 8080, 1, status='401', request_in=1),
            r(3, 3, 'a', 's', 1, 8080, 'GET', '/manager/status.xsd'),
            r(4, 4, 's', 'a', 8080, 1, status='200', request_in=3),
        ]
        analysis = analyze_http(rows)
        self.assertNotIn('possible_manager_access_after_401', [o['type'] for o in analysis['observations']])

    def test_http_200_before_401_is_not_success_candidate(self):
        rows = [
            r(1, 1, 'a', 's', 1, 8080, 'GET', '/manager/html'),
            r(2, 2, 's', 'a', 8080, 1, status='200', request_in=1),
            r(3, 3, 'a', 's', 1, 8080, 'GET', '/manager/html'),
            r(4, 4, 's', 'a', 8080, 1, status='401', request_in=3),
        ]
        analysis = analyze_http(rows)
        self.assertNotIn('possible_manager_access_after_401', [o['type'] for o in analysis['observations']])

    def test_safe_path_and_scanner(self):
        self.assertEqual(safe_http_path('/login?password=secret'), '/login')
        self.assertEqual(safe_http_path('/token/abcdef?x=y'), '/token/[REDACTED]')
        self.assertEqual(scanner_identifiers('Mozilla gobuster/3.6 hello foo=secret'), ['gobuster/3.6'])


if __name__ == '__main__':
    unittest.main()
