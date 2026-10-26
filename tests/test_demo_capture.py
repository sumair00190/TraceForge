import struct
import tempfile
import unittest
from pathlib import Path

from scripts.generate_demo_capture import build_packets, build_scan_packets, write_demo


class DemoCaptureTests(unittest.TestCase):
    def test_six_synthetic_frames(self):
        packets = build_packets()
        self.assertEqual(len(packets), 6)
        self.assertEqual([p[12:14].hex() for p in packets],
                         ['0806', '0800', '0800', '0800', '0800', '0800'])

    def test_pcap_structure_and_deterministic_output(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'demo.pcap'
            write_demo(target)
            data = target.read_bytes()
            self.assertEqual(struct.unpack('<IHHIIII', data[:24]),
                             (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            offset = 24
            count = 0
            while offset < len(data):
                _, _, saved, original = struct.unpack('<IIII', data[offset:offset + 16])
                self.assertEqual(saved, original)
                offset += 16 + saved
                count += 1
            self.assertEqual(count, 6)
            self.assertEqual(offset, len(data))
            write_demo(target)
            self.assertEqual(data, target.read_bytes())
    
    def test_offline_scan_scenario_is_distinct_and_deterministic(self):
        packets = build_scan_packets()
        self.assertEqual(len(packets), 18)
        self.assertEqual(packets[:6], build_packets())
        self.assertTrue(all(p[12:14].hex() == '0800' for p in packets[6:]))
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'scan.pcap'
            write_demo(target, 'scan')
            first = target.read_bytes()
            write_demo(target, 'scan')
            self.assertEqual(first, target.read_bytes())
            offset = 24
            count = 0
            while offset < len(first):
                _, _, saved, original = struct.unpack('<IIII', first[offset:offset + 16])
                self.assertEqual(saved, original)
                offset += 16 + saved
                count += 1
            self.assertEqual(count, 18)
            self.assertEqual(offset, len(first))

    def test_unknown_scenario_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                write_demo(Path(temp) / 'wrong.pcap', 'missing')

    def test_pcapng_blocks_and_determinism(self):
        for scenario, count in (("baseline", 6), ("scan", 18)):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "sample.pcapng"
                write_demo(target, scenario)
                data = target.read_bytes()
                self.assertEqual(struct.unpack("<I", data[:4])[0], 0x0A0D0D0A)
                self.assertEqual(struct.unpack("<I", data[4:8])[0], 28)
                self.assertEqual(struct.unpack("<I", data[28:32])[0], 1)
                offset, packets = 0, 0
                while offset < len(data):
                    kind, size = struct.unpack("<II", data[offset:offset + 8])
                    self.assertGreaterEqual(size, 12)
                    self.assertEqual(size % 4, 0)
                    self.assertEqual(struct.unpack("<I", data[offset + size - 4:offset + size])[0], size)
                    if kind == 6:
                        packets += 1
                        caplen = struct.unpack("<I", data[offset + 20:offset + 24])[0]
                        self.assertGreater(caplen, 0)
                    offset += size
                self.assertEqual(offset, len(data))
                self.assertEqual(packets, count)
                write_demo(target, scenario)
                self.assertEqual(target.read_bytes(), data)

    def test_cap_alias_uses_classic_pcap(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "sample.cap"
            write_demo(target)
            self.assertEqual(target.read_bytes()[:4], bytes.fromhex("d4c3b2a1"))
