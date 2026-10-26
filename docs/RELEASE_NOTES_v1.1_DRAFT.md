# TraceForge v1.1.0 — Draft GitHub Release Notes

**Status: DRAFT.** Do not publish before final approval. The repository remains private, the annotated source tag `v1.1.0` exists, and the separate GitHub Release page has **not** been created. Tagged `v1.0` is unchanged.

TraceForge is an offline Python/TShark network-forensics triage utility for authorized PCAP, PCAPNG and CAP captures. It produces evidence-backed investigation leads with standalone HTML and JSON reports. It is not a universal intrusion detection system.

## What's new since v1.0

- Installable `traceforge` and `traceforge-batch` CLI commands for single-file and multi-capture investigations.
- Deterministic synthetic PCAP and PCAPNG examples, including an intentionally simulated 13-port SYN scan candidate with supporting Wireshark frame references.
- Capture-wide protocol landscape and a new **Investigation at a glance** panel in the offline HTML dashboard.
- Batch summary dashboard, numbered per-capture reports and isolated error handling for unreadable inputs.
- Optional input-file SHA-256 fingerprint in reports, alongside analyzed-at UTC time, TShark version and configuration metadata.
- Configurable TCP SYN scan sensitivity profiles: `sensitive` (5 unique ports), `balanced` (10), `conservative` (25), plus validated JSON settings.
- GitHub Actions Python 3.10 and 3.13 unit tests and TShark integration demos for PCAP, PCAPNG, CAP, batch analysis and profiles.
- Source licensing and community documents prepared for an **Apache-2.0** open-source launch; includes LICENSE and NOTICE.

## Quick start

Requires **Python 3.10+** and **TShark** on PATH.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
python3 scripts/generate_demo_capture.py --scenario scan --output demo/traceforge-scan-demo.pcapng
traceforge demo/traceforge-scan-demo.pcapng --profile balanced --fingerprint
xdg-open reports/traceforge-scan-demo-report.html
```

Batch demonstration:

```bash
traceforge-batch demo --output-dir reports/batch --max-files 10
xdg-open reports/batch/batch-report.html
```

## Validation and caveats

- **85 Python tests passed on tagged v1.1.0 in Kali**; GitHub Actions passed on Python 3.10/3.13 with synthetic TShark, package licensing and version checks.
- **Tagged v1.1.0 validated on Kali:** both CLIs reported version 1.1.0, and the synthetic 18-packet PCAPNG produced one evidence-backed SYN review finding. Public-launch privacy review, screenshots and explicit publication approval remain outstanding.
- Synthetic findings do not establish detection accuracy on real-world malicious or benign traffic.
- Encrypted application content, unsupported protocols, truncated captures, missing packets and TShark limitations can cause missed or ambiguous results.
- Output IP addresses, timestamps, evidence frames and capture metadata may be sensitive. Review all reports before sharing.
- SHA-256 is a file fingerprint and **not** proof of forensic chain of custody.
- The tool is read-only and offline; packet interpretation requires analyst confirmation.

Documentation: [Quickstart](../README.md) · [Five-minute demo](DEMO.md) · [Validation](VALIDATION.md) · [Privacy boundaries](ARCHITECTURE.md) · [License](../LICENSE)

**Do not claim independent benchmark accuracy, production IDS readiness, guaranteed attack detection, confirmed exploit success or complete encrypted-traffic decryption.**
