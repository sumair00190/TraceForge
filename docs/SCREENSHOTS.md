# Public launch screenshot checklist (synthetic traffic only)

The first public TraceForge screenshots should be **reproducible** and show no private or third-party capture data. Do not attach actual incident PCAPs or unredacted reports.

## Generate a clean demonstration

In Kali, from the TraceForge project with the Python virtual environment active:

```bash
python3 scripts/generate_demo_capture.py --scenario scan --output demo/traceforge-launch-demo.pcapng
traceforge --fingerprint demo/traceforge-launch-demo.pcapng --profile balanced --output-dir reports/launch-demo
xdg-open reports/launch-demo/traceforge-launch-demo-report.html
```

**Expected:** 18 synthetic packets, 13 unique probed destination ports, one possible SYN scan candidate, frame 5 as its first evidence reference, and SHA-256 provenance. The 192.0.2.0/24 and 198.51.100.0/24 networks shown by the generator are reserved documentation address ranges. Capture and analysis timestamps may differ: the demo packet times are fixed historical timestamps.

## Suggested images

1. **Investigation overview** — report title, 18 packets and the "Investigation at a glance" panel.
2. **Evidence trail** — the candidate scan finding, source/destination *documentation-only* IPs and frame references.
3. **Terminal proof (optional)** — `python3 -m unittest discover -s tests -q` ending in `Ran 85 tests` / `OK`, plus CLI version `1.1.0`. Do not show shell tokens or GitHub login prompts.

Capture the page itself (for example, Firefox's built-in Screenshot option) rather than the full desktop. Review screenshots for home directory names, usernames, tabs, notifications, email addresses, login URLs, secrets, personally identifying data or any unrelated browser content before sharing.

Reviewed, cropped synthetic screenshots are now committed at [`docs/images/traceforge-overview.png`](images/traceforge-overview.png) and [`docs/images/traceforge-evidence.png`](images/traceforge-evidence.png), and are shown in the README. Do not replace them with private captures or screenshots exposing browser tabs, file paths or unrelated accounts.

Label every screenshot **"Synthetic offline demonstration — heuristic alert, not confirmed malicious traffic"** in the caption or surrounding publication text.

The synthetic screenshots and README gallery are complete. Do not make the repository public, publish a new GitHub Release, post on LinkedIn or upload to a package index without explicit authorization.
