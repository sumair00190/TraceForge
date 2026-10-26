# Changelog

## v1.1.0 — Tagged source version (private; GitHub Release pending)

- Added installable CLI, GitHub Actions Python/TShark checks, synthetic PCAP/PCAPNG/CAP demos, offline analyst overview, and optional capture SHA-256 provenance.
- Added multi-capture batch analysis with separate reports and a consolidated dashboard.
- Added configurable SYN scan sensitivity profiles and validated local JSON settings, verified against synthetic captures.
- Prepared Apache License 2.0 distribution: LICENSE, NOTICE, SPDX headers, wheel metadata, security/contributing/community documentation and issue templates.
- **Release status:** The `v1.1.0` annotated tag points to commit `f687af6`; source remains in a **private** repository and there is **no separate v1.1 GitHub Release**. The tagged `v1.0` is unchanged. Kali verified 85 Python tests, both CLI versions, and a synthetic PCAPNG with 1 SYN scan candidate, evidence frames and SHA-256. Public-launch privacy review, demo screenshots and owner approval remain pending.
- The detection heuristics are limited and subject to false positives/negatives. Reports are not proof of compromise or chain-of-custody certification.


## v1.0 — First functional release (2026-10-19)

- Promoted RC3 feature set to v1.0 with no new detection algorithms.
- Kali: 54 unit tests passed; PsExec, DNS/ICMP and TLS/HTTP training captures validated.
- Read-only offline PCAP/PCAPNG/CAP processing, protocol inventory, evidence-led SMB/HTTP/DNS/ICMP/TLS/SYN triage and HTML/JSON reports.
- **Limits:** no universal attack coverage or formal false-positive benchmark; the Tomcat capture was unavailable for final-version regression. Validate all reported indicators manually.

## v1.0-rc3 — General-purpose protocol inventory / dashboard

- Added capture-wide inventory from `frame.protocols` with exactly one primary protocol family per packet, even for unsupported attack heuristics.
- Recognizes common dissector families including ARP, ICMPv6, IPv6, DNS, TLS, SMB, QUIC, SSH, HTTP/2, and transport-only/undecoded traffic. This is **coverage**, not automatic malicious-activity classification.
- Added capture duration, on-wire byte count, IPv6/non-IP totals, CLI summary, and offline HTML protocol bars.
- Streamed the new metadata through the existing first TShark pass; no extra full-capture inventory pass.
- Added nine offline tests (54 total). Kali verification completed on PsExec Hunt (40,294 packets), DNS/ICMP (33 packets), and TLS/HTTP (17 packets). The prior Tomcat capture is missing locally, so RC3 Tomcat regression remains pending.

## v1.0-rc2.1 — SMB2 detection compatibility patch

- Added narrow SMB2 filename-filter evidence pass to recover `PSEXESVC.exe` references hidden by multi-command field-occurrence differences in TShark.
- Added conservative classification when the Create/Write command cannot be confirmed from exported fields.
- Made SMB2 response flag parsing accept hex representations.
- Added 5 offline regression tests; total 45 passing unit tests.
- **Real PCAP status:** RC2 observed 37,686 SMB2 packets and ADMIN$/IPC$ shares but 0 service-file candidates; RC2.1 still requires a user-run test before claiming the miss is corrected.

## v1.0-rc2 — SMB2/PsExec investigation + dark SOC-style offline report

- Added bounded SMB2 request triage with `smb2.cmd`, Tree Connect share classification, and `PSEXESVC.exe` Create / same-stream Write evidence correlation.
- Detects known share types (`ADMIN$`, `IPC$`, and drive admin shares) without exporting arbitrary UNC paths or hostnames.
- Added SMB2/PsExec sections to CLI, JSON, attack timeline and standalone HTML report.
- Updated HTML layout to use a dark SOC-style palette; still offline and print-friendly.
- Added eight tests: seven SMB parser and privacy tests plus an integration smoke test (40 total).
- Actual PsExec Hunt PCAP must still be verified on Kali; this is **not** a stable release or a validated IDS.

## v1.0-rc1
- Organized a release-candidate ZIP with source, tests, README, changelog, and .gitignore.
- Added `--version`, `--output-dir`, file-extension validation, and safer output filenames.
- Preserved all v0.9 SYN, HTTP, DNS, ICMP, TLS, correlation, JSON, and HTML capabilities.
- Added basic CLI option/filename regression tests.

## v0.9
- Added evidence-based TLS handshake metadata analysis and reports.

## v0.8
- Added ICMP Echo matching and sweep heuristics.

## v0.7.2
- Fixed DNS Boolean format handling.

## v0.7.1
- Fixed TCP stream handshake parsing.

## v0.5–v0.7
- Added offline HTML reports, DNS analysis, and outbound SYN correlation.

## v0.1–v0.4
- Added packet overview, SYN scan detection, HTTP analysis, and attack timeline.
