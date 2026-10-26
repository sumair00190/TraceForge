"""Smoke test for SMB wiring through main analyzer without a TShark binary."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import traceforge


class SMBIntegrationTests(unittest.TestCase):
    def test_analyze_includes_smb_in_timeline_and_html(self):
        def fake_rows(capture, fields, display_filter=None):
            if display_filter == traceforge.SMB_FILTER:
                return iter([
                    ('1', '1700000001', '10.0.0.130', '', '10.0.0.133', '', '123', '3', 'False',
                     r'\\10.0.0.133\ADMIN$', '', ''),
                    ('2', '1700000002', '10.0.0.130', '', '10.0.0.133', '', '123', '5', 'False',
                     '', 'PSEXESVC.exe', ''),
                    ('3', '1700000003', '10.0.0.130', '', '10.0.0.133', '', '123', '9', 'False',
                     '', 'PSEXESVC.exe', '500'),
                ])
            return iter([])
        with patch.object(traceforge, 'tshark_rows', side_effect=fake_rows):
            result = traceforge.analyze(Path('fixture.pcapng'), 10)
        self.assertEqual(result['smb_analysis']['decoded_packets'], 3)
        self.assertEqual(len(result['smb_analysis']['observations']), 1)
        self.assertIn('smb_psexec_service_file_candidate', [ev['event'] for ev in result['timeline']])
        html = traceforge.render_html_report(result)
        self.assertIn('SMB2 / PsExec Investigation', html)
        self.assertIn('PSEXESVC.exe', html)
        self.assertIn('--panel:#122239', html)


if __name__ == '__main__':
    unittest.main()
