# TraceForge Architecture

TraceForge is an offline, read-only network-forensics **triage** utility. Its core is a Python 3.10+ standard-library application that invokes the locally installed TShark executable.

## Processing flow

1. Validate the user-selected PCAP, PCAPNG or CAP path and command-line options.
2. Ask TShark to decode metadata and relevant traffic subsets. Packet content is read from the provided file; no live capture, scanning or cloud API calls are used.
3. Build a capture-wide inventory from packet timestamps, wire lengths, protocol stacks and IPv4/IPv6 metadata.
4. Independently summarize TCP SYN probes, HTTP/1.x requests and responses, DNS, ICMPv4 Echo, TLS handshake metadata, SMB2 metadata, and selected network-flow correlations.
5. Correlate observations into an investigation timeline with packet/frame references.
6. Write an evidence-backed JSON result and a standalone offline HTML report.

## Trust boundaries

- **Input is untrusted.** A capture can be corrupted, truncated, crafted or exceptionally large. TShark must be up-to-date and used in an isolated analysis environment for untrusted captures.
- Generated HTML escapes supplied values and does not load external scripts, CSS or images. HTTP bodies, cookies, authorization headers, DNS names, raw SNI and SMB file contents are not deliberately included in reports.
- IP addresses, timing, frame numbers, filenames and correlation metadata can still be sensitive. Review generated files before public sharing.
- Detection is heuristic and protocol-specific: a result indicates a lead for analyst review, never definitive malicious intent. Empty detections do **not** establish safety.
- Encrypted SMB/TLS and unrecognized dissectors may hide useful activity. IPv6 is included in the inventory; some detailed modules are IPv4-only.
- TShark filters and multiple passes can take time on large captures. This project is not a high-throughput production IDS, a forensic chain-of-custody solution or a malware-classification engine.

## Extending safely

Add a parsing or finding function, include bounded evidence frames and timestamps, ensure untrusted values are escaped/redacted, document limitations, and add unit tests plus a controlled PCAP regression before describing the detection as validated.
