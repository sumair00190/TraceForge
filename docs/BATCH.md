# TraceForge Batch Investigation

Analyze a directory of **authorized** captures with one command and produce per-capture reports plus a combined offline dashboard. No packets are sent or captured.

## Quick start

From an installed virtual environment with TShark available:

```bash
python3 scripts/generate_demo_capture.py --scenario baseline
python3 scripts/generate_demo_capture.py --scenario scan
python3 scripts/generate_demo_capture.py --scenario scan --output demo/scan-compat.pcapng
traceforge-batch demo --output-dir reports/batch --max-files 10
xdg-open reports/batch/batch-report.html
```

Batch mode scans only the selected directory by default. Include subfolders explicitly:

```bash
traceforge-batch /path/to/authorized-captures --recursive --output-dir reports/case-001 --fingerprint
```

The optional `--fingerprint` flag SHA-256 hashes each input capture and adds an extra full-file read.

## Outputs

- `batch-report.json`: compact aggregate inventory of success/failure counts, packet counts and **heuristic review leads**.
- `batch-report.html`: standalone, escaped, dark offline dashboard, with links to successfully generated individual HTML reports.
- `0001-name-report.json` / `0001-name-report.html`: one numbered set of reports per capture. Index prefixes prevent overwrite when the same basename exists in different folders or capture formats.

The batch summary contains **filenames**, not absolute input paths, payloads or packet contents. File names and network metadata can still be sensitive. Do not share reports without reviewing them.

## Reliability controls

- Recognized extensions: `.pcap`, `.pcapng`, `.cap` — real decoding depends on TShark.
- A damaged, unreadable or unsupported capture is marked **failed**, while other files are still processed.
- A nonzero exit code is returned if **any** capture failed. Empty directories and over-limit batches are rejected without analysis.
- Default batch limit: 100 input files, adjustable with `--max-files`. Huge files can still require substantial processing time.
- The default is nonrecursive; `--recursive` is opt-in. Symbolic links to files are ignored.
- Separate captures are processed independently; **counts are not deduplicated** if PCAP files overlap. A shared IP or adjacent timestamps do not, by themselves, establish a cross-capture attack chain.
- Detection remains heuristic and protocol-specific. Zero findings is **not** evidence that the captures are harmless.

If no HTML is wanted, pass `--no-html` to generate only JSON.

For large untrusted captures, work on a trusted, updated TShark installation in an isolated environment. This is not a formal chain-of-custody platform, real-time IDS or enterprise-scale pipeline.

## Validation

The project's GitHub Actions workflow runs the same demo captures in `.pcap`, `.pcapng`, `.cap` forms through the installed `traceforge-batch` CLI and checks combined packet counts, finding counts, report links and per-file fingerprints. The isolated tests also check file discovery, duplicate basenames, partial failures, count limits and HTML escaping.
