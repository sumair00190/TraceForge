"""Capture-wide protocol inventory tests; no real capture or TShark required."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import traceforge


class ProtocolInventoryTests(unittest.TestCase):
    def test_general_protocols_are_classified_without_detection_logic(self):
        stacks = {
            'eth:ethertype:arp': 'ARP',
            'eth:ethertype:ipv6:icmpv6': 'ICMPv6',
            'eth:ethertype:ip:udp:quic': 'QUIC',
            'eth:ethertype:ip:tcp:ssh': 'SSH',
            'eth:ethertype:ip:udp:bootp': 'DHCP',
            'eth:ethertype:ip:udp:dns': 'DNS',
            'eth:ethertype:ip:tcp:smb2': 'SMB2',
            'eth:ethertype:ip:udp': 'UDP (other)',
            'eth:ethertype:ip:tcp': 'TCP (other)',
            'eth:ethertype:ip:tcp:tls:http2': 'HTTP/2',
            'radiotap:wlan:data': 'Other / undecoded',
        }
        for stack, expected in stacks.items():
            with self.subTest(stack=stack):
                self.assertEqual(traceforge.protocol_family(stack), expected)

    def test_empty_protocols_become_other(self):
        self.assertEqual(traceforge.protocol_family(''), 'Other / undecoded')
        self.assertEqual(traceforge.protocol_family(None), 'Other / undecoded')

    def test_capitalized_protocols(self):
        self.assertEqual(traceforge.protocol_family('ETH:IP:TCP:TLS'), 'TLS')

    def test_ipv6_and_non_ip_counts(self):
        inv = traceforge.new_inventory()
        traceforge.add_inventory_packet(inv, '20', '120', 'eth:arp', '', '')
        traceforge.add_inventory_packet(inv, '21', '140', 'eth:ipv6:icmpv6', '', '2001:db8::1')
        traceforge.add_inventory_packet(inv, '22', '160', 'eth:ip:tcp:ssh', '10.0.0.2', '')
        result = traceforge.finish_inventory(inv)
        self.assertEqual(result['non_ip_packets'], 1)
        self.assertEqual(result['ipv6_packets'], 1)
        self.assertEqual(result['total_wire_bytes'], 420)
        self.assertEqual(result['duration_seconds'], 2)
        self.assertEqual(sum(x['packets'] for x in result['primary_protocol_families']), 3)

    def test_out_of_order_time_range_and_invalid_frame_size(self):
        inv = traceforge.new_inventory()
        traceforge.add_inventory_packet(inv, '100', '85', 'ip:udp', '192.0.2.1', '')
        traceforge.add_inventory_packet(inv, '50', '-2', 'ip:tcp', '192.0.2.2', '')
        traceforge.add_inventory_packet(inv, 'nan', 'oops', '', '', '')
        result = traceforge.finish_inventory(inv)
        self.assertEqual(result['duration_seconds'], 50)
        self.assertEqual(result['total_wire_bytes'], 85)
        self.assertEqual(result['invalid_frame_lengths'], 2)

    def test_one_family_per_packet_even_when_nested(self):
        inv = traceforge.new_inventory()
        traceforge.add_inventory_packet(inv, '1', '100', 'eth:ip:tcp:tls:http2', '192.0.2.1', '')
        result = traceforge.finish_inventory(inv)
        self.assertEqual(result['primary_protocol_families'], [{'name': 'HTTP/2', 'packets': 1}])

    def test_html_renders_inventory_and_escapes_untrusted_capture_name(self):
        r = {'capture': 'capture<unsafe>.pcapng', 'total_packets': 1,
             'capture_inventory': {'primary_protocol_families': [{'name': 'ARP', 'packets': 1}],
                                   'total_wire_bytes': 42, 'ipv6_packets': 0, 'non_ip_packets': 1,
                                   'duration_seconds': 0.0}}
        html = traceforge.render_html_report(r)
        self.assertIn('Capture-wide Protocol Landscape', html)
        self.assertIn('protocol-fill', html)
        self.assertIn('ARP', html)
        self.assertIn('Non-IP packets', html)
        self.assertNotIn('capture<unsafe>', html)

    def test_main_analyzer_inventory_without_signatures(self):
        inventory_row = ('1.0', '64', 'eth:ethertype:arp', '', '', '', '', '')
        inventory_row2 = ('2.0', '90', 'eth:ethertype:ipv6:tcp:ssh', '', '2001:db8::1', '', '2001:db8::2', '22')
        def rows(capture, fields, display_filter=None):
            if fields == traceforge.INVENTORY_FIELDS:
                return iter([inventory_row, inventory_row2])
            return iter([])
        with patch.object(traceforge, 'tshark_rows', side_effect=rows):
            result = traceforge.analyze(Path('mixed.pcapng'), 10)
        self.assertEqual(result['total_packets'], 2)
        self.assertEqual(result['ip_packets'], 1)
        self.assertEqual(result['capture_inventory']['non_ip_packets'], 1)
        self.assertEqual(result['capture_inventory']['ipv6_packets'], 1)
        self.assertEqual(result['capture_inventory']['total_wire_bytes'], 154)
        self.assertEqual(result['capture_inventory']['primary_protocol_families'][0]['packets'], 1)
        self.assertEqual(result['alerts'], [])

    def test_no_packets_yields_safe_empty_inventory(self):
        result = traceforge.finish_inventory(traceforge.new_inventory())
        self.assertIsNone(result['duration_seconds'])
        self.assertEqual(result['total_wire_bytes'], 0)
        self.assertEqual(result['primary_protocol_families'], [])

if __name__ == '__main__':
    unittest.main()
