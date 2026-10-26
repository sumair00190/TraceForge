#!/usr/bin/env python3
# Copyright 2026 sumair00190
# SPDX-License-Identifier: Apache-2.0
"""Create harmless, reproducible Ethernet PCAP/PCAPNG demos with reserved IP addresses."""
import argparse
import ipaddress
import struct
from pathlib import Path

SRC = ipaddress.IPv4Address("192.0.2.10").packed
DST = ipaddress.IPv4Address("198.51.100.20").packed
A = bytes.fromhex("020000000001")
B = bytes.fromhex("020000000002")

def checksum(value):
    if len(value) % 2:
        value += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(value) // 2), value))
    while total > 65535:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def eth(data, kind=0x0800, source=A, target=B):
    return target + source + struct.pack("!H", kind) + data

def ipv4(protocol, source, target, data, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(data), ident, 0, 64, protocol, 0, source, target)
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + data

def icmp(kind):
    data = struct.pack("!BBHHH", kind, 0, 0, 11, 1) + b"TraceForge demo"
    return data[:2] + struct.pack("!H", checksum(data)) + data[4:]

def tcp(sport, dport, source, target, flags, seq, ack=0):
    data = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    pseudo = source + target + struct.pack("!BBH", 0, 6, len(data))
    return data[:16] + struct.pack("!H", checksum(pseudo + data)) + data[18:]

def build_packets():
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + A + SRC + bytes(6) + DST
    question = b"\x07example\x04test\x00" + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", 0x1a2b, 0x0100, 1, 0, 0, 0) + question
    udp = struct.pack("!HHHH", 53000, 53, len(query) + 8, 0) + query
    return [
        eth(arp, 0x0806, target=b"\xff" * 6),
        eth(ipv4(17, SRC, DST, udp, 1)),
        eth(ipv4(1, SRC, DST, icmp(8), 2)),
        eth(ipv4(1, DST, SRC, icmp(0), 3), source=B, target=A),
        eth(ipv4(6, SRC, DST, tcp(50000, 443, SRC, DST, 0x02, 1), 4)),
        eth(ipv4(6, DST, SRC, tcp(443, 50000, DST, SRC, 0x12, 20, 2), 5), source=B, target=A),
    ]

def build_scan_packets():
    """Simulated SYN fan-out in a file; never sends packets to the network."""
    packets = build_packets()
    for i in range(12):
        port = 9000 + i
        payload = tcp(50100 + i, port, SRC, DST, 0x02, 100 + i)
        packets.append(eth(ipv4(6, SRC, DST, payload, 10 + i)))
    return packets

def write_demo(path, scenario="baseline"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets() if scenario == "baseline" else build_scan_packets() if scenario == "scan" else None
    if packets is None:
        raise ValueError("Unknown demo scenario")
    with path.open("wb") as output:
        if path.suffix.lower() == ".pcapng":
            # PCAPNG Section Header + Ethernet Interface Description blocks.
            output.write(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28))
            output.write(struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20))
            for i, packet in enumerate(packets):
                # Enhanced Packet Block timestamps use 1-microsecond units.
                timestamp = (1700000000 + i) * 1000000
                padding = bytes((-len(packet)) % 4)
                size = 32 + len(packet) + len(padding)
                output.write(struct.pack("<IIIIIII", 6, size, 0, timestamp >> 32,
                                         timestamp & 0xFFFFFFFF, len(packet), len(packet)))
                output.write(packet)
                output.write(padding)
                output.write(struct.pack("<I", size))
        else:
            # Classic little-endian libpcap, including the .cap alias.
            output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, packet in enumerate(packets):
                output.write(struct.pack("<IIII", 1700000000 + i, 0, len(packet), len(packet)))
                output.write(packet)
    return path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["baseline", "scan"], default="baseline",
                        help="baseline: ordinary traffic; scan: simulated TCP SYN fan-out")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    destination = args.output or Path("demo/traceforge-scan-demo.pcap" if args.scenario == "scan" else "demo/traceforge-demo.pcap")
    count = 18 if args.scenario == "scan" else 6
    print(f"Generated {count} synthetic frames ({args.scenario}):", write_demo(destination, args.scenario))

if __name__ == "__main__":
    main()
