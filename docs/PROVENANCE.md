# Capture provenance and reproducibility

TraceForge includes optional **SHA-256** capture fingerprinting to help analysts match a report to the file they examined.

## Generate a fingerprinted report

```bash
traceforge --fingerprint "/path/to/authorized-capture.pcapng"
```

The generated JSON has `capture_provenance`; the offline HTML contains a **Capture provenance** section. Information includes:

- Input basename and size in bytes (not the full local path)
- Capturing file format extension
- TraceForge build version and TShark's reported version
- Analysis timestamp in UTC
- Configured SYN-scan threshold
- Optional SHA-256 hash of the input file's raw bytes

The SHA-256 digest can be independently checked with:

```bash
sha256sum "/path/to/authorized-capture.pcapng"
```

A SHA-256 digest is a **file fingerprint, not proof of collection integrity, authenticity, absence of tampering, or legal chain of custody**. The current implementation assumes the capture is not being modified concurrently. Record full acquisition details, custody, permissions and relevant hashes using your organization's forensic procedures.

For very large files, the extra read required for hashing can increase analysis time. Without `--fingerprint`, no full-file hash is computed. The report may still contain sensitive IP addresses and timing evidence; inspect it before sharing.

GitHub Actions checks this feature using a deterministic, synthetic PCAP; no private real-world captures are bundled.
