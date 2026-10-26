"""Regression coverage for TShark's filtered filename / first-occurrence gap."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import traceforge


def row(frame, cmd, stream='10', filename='', response='False'):
    return (str(frame), str(1700000000 + frame), '10.0.0.130', '',
            '10.0.0.133', '', stream, str(cmd), response, '', filename, '')


class SMBFilterFallbackTests(unittest.TestCase):
    def test_filter_evidence_recovers_filename_hidden_by_compound(self):
        summary = traceforge.analyze_smb([row(144, 5), row(145, 9)])
        self.assertEqual(summary['observations'], [])
        recovered = traceforge.supplement_smb_service_evidence(summary, [row(144, 5), row(145, 9)])
        self.assertEqual(len(recovered['observations']), 1)
        self.assertEqual(recovered['observations'][0]['assessment'], 'explicit_file_create_and_write')
        self.assertEqual(recovered['observations'][0]['sample_packet_numbers'], ['144','145'])
        self.assertEqual(recovered['timeline'][0]['sample_frame'], '144')

    def test_uncertain_operation_uses_conservative_classification(self):
        summary = traceforge.analyze_smb([])
        recovered = traceforge.supplement_smb_service_evidence(summary, [row(144, 'garbled')])
        self.assertEqual(len(recovered['observations']), 1)
        self.assertEqual(recovered['observations'][0]['assessment'],
                         'filename_filtered_activity_verify_create_and_write')

    def test_no_duplicate_if_normal_pass_recognizes_create(self):
        summary = traceforge.analyze_smb([row(144, 5, filename='PSEXESVC.exe')])
        self.assertEqual(len(summary['observations']), 1)
        recovered = traceforge.supplement_smb_service_evidence(summary, [row(144, 5)])
        self.assertEqual(len(recovered['observations']), 1)

    def test_responses_not_counted_and_hex_flag_parsed(self):
        self.assertTrue(traceforge._flag_value('0x00000001'))
        self.assertFalse(traceforge._flag_value('0x00000000'))
        summary = traceforge.analyze_smb([])
        recovered = traceforge.supplement_smb_service_evidence(summary, [row(144, 5, response='0x1')])
        self.assertEqual(recovered['observations'], [])

    def test_pipeline_runs_filtered_fallback(self):
        def fake_rows(capture, fields, filt=None):
            if filt == traceforge.SMB_FILTER:
                return iter([row(144, 5), row(145, 9)])
            if filt == traceforge.SMB_SERVICE_FILTER:
                return iter([row(144, 5), row(145, 9)])
            return iter([])
        with patch.object(traceforge, 'tshark_rows', side_effect=fake_rows):
            result = traceforge.analyze(Path('authorized.pcapng'), 10)
        self.assertEqual(len(result['smb_analysis']['observations']), 1)
        self.assertIn('smb_psexec_service_file_candidate',
                      [e['event'] for e in result['timeline']])
        html = traceforge.render_html_report(result)
        self.assertIn('SMB2 / PsExec Investigation', html)


if __name__ == '__main__':
    unittest.main()
