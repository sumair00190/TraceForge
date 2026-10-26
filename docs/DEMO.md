# TraceForge — Five-minute offline demo

This walkthrough requires **no external connection, live scan, or private traffic capture**. It reproduces two controlled outcomes for an evaluator using documentation-only source and destination addresses.

## 1. Install in a disposable environment

```bash
git clone https://github.com/sumair00190/TraceForge.git
cd TraceForge
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
traceforge --version
```

Install a local TShark package separately if it is not on your PATH. While the GitHub repository is private, the clone link is available only to authorized collaborators.

## 2. Baseline — no supported scan alert

```bash
python3 scripts/generate_demo_capture.py --scenario baseline
traceforge demo/traceforge-demo.pcap
```

Expected for this exact deterministic fixture:
- 6 packets: 1 ARP, 1 DNS, 2 ICMPv4, 2 TCP
- 1 SYN destination port; **0** threshold-based SYN scan alerts
- 1 matched ICMP Echo reply
- HTML and JSON reports in `reports/`

## 3. Simulated investigation — a review finding

```bash
python3 scripts/generate_demo_capture.py --scenario scan
traceforge demo/traceforge-scan-demo.pcap
xdg-open reports/traceforge-scan-demo-report.html
```

Expected on this synthetic fixture:
- 18 packets, including 13 TCP SYN frames to 13 destination ports
- **1** possible SYN scan alert for `192.0.2.10 -> 198.51.100.20`
- Evidence frames **5, 7, 8, 9, 10**, and an investigation timeline item at frame **5**
- Analyst overview shows the number of supported heuristic review findings
- HTML and JSON reports are generated entirely offline

The alert is intentionally triggered by synthetic data. It does not establish performance on real attacks. In a real investigation, the analyst should validate the source and traffic context before deciding whether a scan was authorized.

## 4. Review evidence in Wireshark

Open `demo/traceforge-scan-demo.pcap` in Wireshark and apply:

```
frame.number == 5
```

To see all the synthetic SYN probes:

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Capture-level evidence can be cross-checked with the JSON report instead of trusting an opaque score.

## 5. Suggested portfolio screenshots

1. Terminal showing `traceforge --version` and the **successful synthetic alert**.
2. Dashboard top section with **Investigation at a glance** and protocol inventory.
3. Timeline and the SYN scan evidence card with numbered frames.
4. GitHub Actions checks (Python 3.10, Python 3.13, TShark integration).

Label all screenshots as **synthetic demo / simulated network activity**. Do not claim they are real compromises. Never upload private PCAPs or unreviewed reports without permission.

## Practical limitations

This is an evidence-led analyst-assistance project, **not** a general-purpose malware detector. Some protocols receive only protocol inventory. The project has not undergone independent accuracy benchmarking, large-scale performance testing or complete false-positive evaluation.

To exercise the tests: `python3 -m unittest discover -s tests -q`.
