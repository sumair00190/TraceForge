"""New functionality added in v0.6."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import analyze_dns, correlate_outbound_syn, summarize_syn_probes, render_html_report


class NetworkExtensionsTests(unittest.TestCase):
    def test_dns_weak_signals_and_privacy(self):
        confidential_domain = 'A' * 51 + '.example.invalid'
        rows = [
            ('10', '100.0', '192.0.2.11', '', '0', confidential_domain, '1', ''),
            ('11', '100.1', '192.0.2.53', '', '1', confidential_domain, '1', '0'),
            ('12', '100.2', '192.0.2.11', '', '0', 'ordinary.example.invalid', '28', ''),
        ]
        result = analyze_dns(rows, burst_threshold=10)
        self.assertEqual(result['queries'], 2)
        self.assertEqual(result['responses'], 1)
        self.assertEqual(result['query_types'], {'1':1, '28':1})
        self.assertEqual(result['observations'][0]['type'], 'dns_long_label_review')
        self.assertEqual(result['observations'][0]['sample_packet_numbers'], ['10'])
        self.assertNotIn('example.invalid', str(result))
        html = render_html_report({'capture':'test.pcap', 'total_packets':3, 'dns_analysis':result})
        self.assertNotIn('example.invalid', html)
        self.assertIn('DNS review signals', html)

    def test_dns_boolean_output_from_tshark(self):
        # FT_BOOLEAN has appeared as True/False rather than 1/0 in TShark.
        rows = [
            ('20', '111.0', '192.0.2.5', '', 'False', 'safe.example.invalid', '1', '0'),
            ('21', '111.2', '192.0.2.53', '', 'True', 'safe.example.invalid', '1', '0'),
            ('22', '111.3', '192.0.2.5', '', '0', 'another.example.invalid', '28', '0'),
            ('23', '111.4', '192.0.2.53', '', '1', 'another.example.invalid', '28', '0'),
            ('24', '111.5', '192.0.2.5', '', '', 'unknown.example.invalid', '1', '0'),
        ]
        result = analyze_dns(rows)
        self.assertEqual(result['queries'], 2)
        self.assertEqual(result['responses'], 2)
        self.assertEqual(result['top_query_clients'], [('192.0.2.5', 2)])
        self.assertNotIn('safe.example.invalid', str(result))

    def test_outbound_after_post_and_not_before(self):
        syn_rows = [
            ('1','10.0','203.0.113.50','','10.0.0.112','','22'),
            ('2','11.0','203.0.113.50','','10.0.0.112','','80'),
            ('3','12.0','203.0.113.50','','10.0.0.112','','443'),
            ('4','14.0','10.0.0.112','','203.0.113.50','','80'),
            ('5','30.0','10.0.0.112','','203.0.113.50','','443'),
        ]
        scans = summarize_syn_probes(syn_rows, 3)
        http = {'timeline': [
            {'event':'management_post_candidate','time_epoch':20.0,'sample_frame':'9',
             'source_ip':'203.0.113.50','destination_ip':'10.0.0.112'}
        ]}
        correlated = correlate_outbound_syn(scans, http)
        self.assertEqual(len(correlated['observations']), 1)
        self.assertEqual(correlated['observations'][0]['ports'], ['443'])
        self.assertEqual(correlated['observations'][0]['sample_packet_numbers'], ['5'])
        self.assertEqual(correlated['timeline'][0]['sample_frame'], '5')
        self.assertNotIn('80', str(correlated))

    def test_outbound_without_post_not_flagged(self):
        scans = summarize_syn_probes([
            ('1','1','a','','b','','21'), ('2','2','a','','b','','22'),
            ('3','3','b','','a','','443'),
        ],2)
        self.assertFalse(correlate_outbound_syn(scans, {'timeline':[]})['observations'])

    def test_untrusted_dns_client_escaped(self):
        dns = analyze_dns([('1', '1.0', '<img src=x>', '', '0', 'A'*49+'.test', '1', '')])
        html = render_html_report({'capture': 'test.pcap', 'dns_analysis': dns})
        self.assertNotIn('<img src=x>', html)
        self.assertIn('&lt;img src=x&gt;', html)

if __name__ == '__main__':
    unittest.main()
