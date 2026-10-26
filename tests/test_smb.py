"""SMB2 parser regression tests: authorized passive traffic metadata only."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import SMB_FIELDS, analyze_smb, render_html_report, _smb2_command


def row(frame, src='10.0.0.130', dst='10.0.0.133', cmd=3, response='False',
        share='', filename='', stream='21'):
    return (str(frame), str(1700000000 + frame), src, '', dst, '',
            stream, str(cmd), response, share, filename, '')


class SMBTests(unittest.TestCase):
    def test_field_shape(self):
        self.assertEqual(len(SMB_FIELDS), len(row(1)))
        self.assertEqual(_smb2_command('0x0005'), 5)
        self.assertEqual(_smb2_command('05'), 5)
        self.assertIsNone(_smb2_command('garbage'))

    def test_admin_shares_and_service_evidence(self):
        records = [
            row(1, share=r'\\10.0.0.133\IPC$'),
            row(2, share=r'\\10.0.0.133\ADMIN$'),
            row(144, cmd=5, filename='PSEXESVC.exe'),
            row(145, cmd=9, filename='PSEXESVC.exe'),
            row(146, cmd=9, filename='PSEXESVC.exe'),
        ]
        got = analyze_smb(records)
        self.assertEqual(got['decoded_packets'], 5)
        self.assertEqual(got['requests'], 5)
        self.assertEqual(got['top_pairs'][0]['administrative_shares'], ['ADMIN$', 'IPC$'])
        self.assertEqual(got['observations'][0]['sample_packet_numbers'], ['144', '145', '146'])
        self.assertEqual(got['observations'][0]['explicit_write_requests'], 2)
        self.assertEqual(got['observations'][0]['assessment'], 'explicit_file_create_and_write')
        self.assertEqual(got['timeline'][0]['event'], 'smb_psexec_service_file_candidate')

    def test_no_false_alert_on_admin_share_alone(self):
        got = analyze_smb([
            row(1, share=r'\\server\ADMIN$'),
            row(2, cmd=5, filename='report.exe'),
            row(3, cmd=9, filename='report.exe'),
        ])
        self.assertEqual(got['observations'], [])
        self.assertEqual(got['timeline'], [])

    def test_do_not_store_server_names_usernames_or_arbitrary_filenames(self):
        rows = [
            row(1, share=r'\\SECRET-SERVER\ADMIN$'),
            row(2, cmd=5, filename=r'C:\Private\passwords.txt'),
            row(3, cmd=5, filename=r'PSEXESVC.exe'),
        ]
        got = analyze_smb(rows)
        self.assertNotIn('SECRET-SERVER', str(got))
        self.assertNotIn('passwords.txt', str(got))
        self.assertEqual(len(got['observations']), 1)
        self.assertEqual(got['observations'][0]['assessment'], 'file_create_only_verify_write')

    def test_responses_and_unrelated_writes_do_not_count(self):
        got = analyze_smb([
            row(1, cmd=5, filename='PSEXESVC.exe', response='True'),
            row(2, cmd=5, filename='PSEXESVC.exe', stream='5'),
            row(3, cmd=9, filename='PSEXESVC.exe', stream='6'),
            row(4, cmd=9, filename='unrelated.txt', stream='5'),
        ])
        self.assertEqual(got['requests'], 3)
        self.assertEqual(got['observations'][0]['explicit_write_requests'], 0)

    def test_render_html_escapes_observation_ips(self):
        got = analyze_smb([
            row(1, src='<script>bad</script>', cmd=5, filename='PSEXESVC.exe'),
        ])
        html = render_html_report({'smb_analysis': got})
        self.assertIn('SMB2 / PsExec Investigation', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertNotIn('<script>bad</script>', html)
        self.assertIn('PSEXESVC.exe', html)

    def test_other_share_names_not_exposed(self):
        got = analyze_smb([
            row(1, share=r'\\server\Confidential HR'),
            row(2, share=r'\\server\C$'),
        ])
        self.assertEqual(got['top_pairs'][0]['administrative_shares'], ['DRIVE_ADMIN_SHARE'])
        self.assertNotIn('Confidential HR', str(got))


if __name__ == '__main__':
    unittest.main()
