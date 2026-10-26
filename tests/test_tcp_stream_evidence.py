"""TraceForge v0.7: packet metadata correlation tests (no capture needed)."""
import sys
import unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import summarize_outbound_stream_packets, render_html_report, _syn_candidate_frames, _packet_info, enrich_outbound_connections


class TCPStreamEvidenceTests(unittest.TestCase):
    def test_separate_tcp_streams_and_detect_handshake(self):
        seeds = [
            (0, '12', '443', '100', '10.0.0.112', '14.0.0.120'),
            (0, '13', '80', '101', '10.0.0.112', '14.0.0.120'),
        ]
        def packet(frame, src, dst, sport, dport, stream, syn='0', ack='1', length='0'):
            return (frame, '100.0', src, '', dst, '', sport, dport, stream, syn, ack, length, '')
        rows = [
            packet('100', '10.0.0.112','14.0.0.120','34001','443','12','1','0'),
            packet('101', '10.0.0.112','14.0.0.120','34002','80','13','1','0'),
            packet('102', '14.0.0.120','10.0.0.112','443','34001','12','1','1'),
            packet('103', '10.0.0.112','14.0.0.120','34001','443','12','0','1','128'),
            packet('104', '14.0.0.120','10.0.0.112','443','34001','12','0','1','42'),
        ]
        result = summarize_outbound_stream_packets(seeds, rows)
        self.assertEqual(len(result[0]), 2)
        http, tls = result[0]
        self.assertEqual(http['destination_port'], '80')
        self.assertFalse(http['syn_ack_observed'])
        self.assertEqual(tls['destination_port'], '443')
        self.assertTrue(tls['syn_ack_observed'])
        self.assertEqual(tls['outbound_payload_bytes'], 128)
        self.assertEqual(tls['inbound_payload_bytes'], 42)
        self.assertEqual(tls['tcp_stream'], '12')

    def test_html_contains_evidence_without_raw_payload(self):
        item = {'type': 'outbound_syn_after_management_post', 'source_ip': '10.0.0.112',
                'destination_ip': '14.0.0.120', 'ports': ['80','443'],
                'sample_packet_numbers': ['100','101'], 'linked_post_frame':'90',
                'connections': [{'destination_port':'443','tcp_stream':'12','syn_frame':'100',
                                 'syn_ack_observed':True,'packets':4,
                                 'outbound_payload_bytes':128,'inbound_payload_bytes':42,
                                 'sample_packet_numbers':['100','102','103']}]}
        report = render_html_report({'capture':'mock.pcap','outbound_correlations':[item]})
        self.assertIn('TCP stream 12', report)
        self.assertIn('payload bytes out/in 128/42', report)
        self.assertIn('SYN-ACK observed', report)


    def test_tshark_boolean_variants(self):
        def row(syn, ack, flags):
            return ('20646', '100.0', '10.0.0.112','', '14.0.0.120','',
                    '39333', '80', '10', syn, ack, '0', flags)
        self.assertTrue(_packet_info(row('True', 'False', ''))['syn'])
        self.assertFalse(_packet_info(row('True', 'False', ''))['ack'])
        self.assertTrue(_packet_info(row('Set', 'Not set', '0x0002'))['syn'])
        self.assertTrue(_packet_info(row('False', 'False', '0x0012'))['ack'])

    def test_live_enrichment_pipeline_with_capture_frame_seeds(self):
        observations = [{
            'source_ip': '10.0.0.112', 'destination_ip': '14.0.0.120',
            'ports': ['80', '443'], 'sample_packet_numbers':['20646','20689']
        }]
        def row(frame, src, dst, sport, dport, stream, flags, bytes_count='0'):
            return (frame, '100.0', src, '', dst, '', sport, dport,
                    stream, 'True' if flags in ('0x0002','0x0012') else 'False',
                    'True' if flags in ('0x0012', '0x0010', '0x0018') else 'False',
                    bytes_count, flags)
        syn = [
            row('20646','10.0.0.112','14.0.0.120','45000','80','9','0x0002'),
            row('20689','10.0.0.112','14.0.0.120','45001','443','10','0x0002'),
        ]
        traffic = syn + [
            row('20647','14.0.0.120','10.0.0.112','80','45000','9','0x0012'),
            row('20690','14.0.0.120','10.0.0.112','443','45001','10','0x0012'),
            row('20692','10.0.0.112','14.0.0.120','45001','443','10','0x0018','55'),
        ]
        with patch('traceforge.tshark_rows', side_effect=[iter(syn),iter(traffic)]) as mock:
            enrich_outbound_connections('dummy.pcap', observations)
        conns = observations[0]['connections']
        self.assertEqual(len(conns),2)
        self.assertEqual([conn['destination_port'] for conn in conns], ['80','443'])
        self.assertTrue(all(conn['syn_ack_observed'] for conn in conns))
        self.assertEqual(conns[1]['outbound_payload_bytes'],55)

    def test_candidate_frames_only_numeric(self):
        self.assertEqual(_syn_candidate_frames([{'sample_packet_numbers':['20','not a frame','10']}]), ['10','20'])

if __name__ == '__main__':
    unittest.main()
