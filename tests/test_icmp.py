import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traceforge import analyze_icmp, render_html_report


def row(frame, epoch, src, dst, typ, code="0", ident="0x0300", seq="1"):
    return (str(frame), str(epoch), src, dst, str(typ), str(code), ident, str(seq))


class ICMPTests(unittest.TestCase):
    def test_four_hosts_not_called_ping_sweep(self):
        source = "192.168.43.9"
        hosts = ["8.8.8.8", "8.8.4.4", "4.2.2.2", "174.137.42.65"]
        rows = []
        frame = 1
        for i, host in enumerate(hosts):
            for seq in range(1, 4):
                rows.append(row(frame, 10+i, source, host, 8, seq=seq)); frame += 1
                if not (i==1 and seq>1):
                    rows.append(row(frame, 10+i+0.1, host, source, 0, seq=seq)); frame += 1
        result=analyze_icmp(rows)
        self.assertEqual(result['echo_requests'], 12)
        self.assertEqual(result['echo_replies'], 10)
        self.assertEqual(result['matched_replies'], 10)
        self.assertEqual(result['requests_without_matching_reply'], 2)
        self.assertEqual(result['top_ping_sources'][0]['distinct_destinations'], 4)
        self.assertEqual(result['observations'], [])
        html=render_html_report({'capture':'dns-icmp.pcapng','icmp_analysis':result})
        self.assertIn('ICMP Echo Investigation', html)
        self.assertIn('12</b>', html)

    def test_icmp_sweep_window_unique_destinations(self):
        rows = [row(i+1, i, '192.0.2.1', '198.51.100.'+str(i+1),8,seq=i+1)
                for i in range(10)]
        result=analyze_icmp(rows)
        self.assertEqual(len(result['observations']),1)
        self.assertEqual(result['observations'][0]['distinct_destinations_in_window'],10)
        self.assertEqual(result['timeline'][0]['event'],'icmp_echo_sweep_candidate')

    def test_same_destination_repeated_not_sweep(self):
        rows=[row(i+1, i, '192.0.2.1','8.8.8.8',8,seq=i+1) for i in range(100)]
        self.assertFalse(analyze_icmp(rows)['observations'])

    def test_slow_unique_targets_not_sweep(self):
        rows=[row(i+1,i*100,'192.0.2.1', '198.51.100.'+str(i+1),8,seq=i+1)
              for i in range(10)]
        self.assertFalse(analyze_icmp(rows)['observations'])

    def test_unmatched_replies_and_unrecognized_types(self):
        rows=[row(1,1,'192.0.2.2','192.0.2.1',0),row(2,2,'192.0.2.1','192.0.2.2',3)]
        r=analyze_icmp(rows)
        self.assertEqual(r['unmatched_replies'],1)
        self.assertEqual(r['echo_requests'],0)
        self.assertEqual(r['icmp_type_counts']['3'],1)

    def test_html_escaping_untrusted_ip(self):
        r=analyze_icmp([row(1,1,'<script>alert(1)</script>','192.0.2.3',8)])
        html=render_html_report({'icmp_analysis':r})
        self.assertNotIn('<script>alert(1)</script>',html)
        self.assertIn('&lt;script&gt;',html)

if __name__ == '__main__': unittest.main()
