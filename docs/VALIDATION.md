# Validation & Known Limits

## Launch verification — 2026-10-26

Owner-provided Kali terminal results: TraceForge 1.1.0, TShark 4.6.6.

| Check | Observed result |
| --- | --- |
| Unit suite | 85 tests passed |
| Synthetic scan | 18 packets; 13 unique ports; 1 SYN scan candidate |
| DNS/ICMP | 33 packets; 6 DNS queries, 5 responses; 12 Echo Requests, 10 replies, 10 matched |
| TLS/HTTP | 17 packets; 2 ClientHello; 2 ServerHello reporting TLS 1.2; 2 HTTP requests and responses |
| PsExec Hunt | 40,294 packets; 4 PSEXESVC.exe candidates; ADMIN$/IPC$ shares |

All four capture runs produced HTML and JSON report paths without reported
errors. These are functional checks, not detection-accuracy benchmarks.
PsExec candidates do not prove malicious execution.

Fresh local history starts at 968d0e4. Old development tags and CI runs
do not belong to this new history. Fresh remote CI and release tagging
remain pending. Training captures and generated reports are excluded
from the launch commit.

## Reproduce the synthetic scan

    python3 -m unittest discover -s tests -q
    python3 scripts/generate_demo_capture.py --scenario scan
    python3 traceforge.py demo/traceforge-scan-demo.pcap

Open reports/traceforge-scan-demo-report.html locally.

## Known limits

- The TCP SYN heuristic counts unique destination ports per source/destination pair across the capture, without a rolling time window. Legitimate activity over a long capture can therefore trigger a candidate.
- HTTP management POST/outbound SYN correlation depends on an existing scan candidate and the first 50 sampled SYNs per pair. Later activity may be missed, and temporal ordering does not prove a reverse shell.

- Unsupported or encrypted protocols: inventory may identify the protocol without a detailed detection.
- No universal detection of attacks, exploit success or malicious intent.
- DNS and ICMP observations are capture-limited; absence of requests or replies does not imply a host is safe or offline.
- No public independent benchmark, no high-volume stress test, and no final-version Tomcat regression yet.
- JSON and HTML reports may reveal address/timing metadata even though application secrets are intentionally omitted.
