# Contributing to TraceForge

Thanks for improving evidence-led, offline network investigation. TraceForge is intended for defensive, authorized analysis only.

## Before you start

- Discuss significant new rules or architectural changes in an issue before implementing them.
- Keep contributions focused and explain which packet observations justify each heuristic. An indicator is not proof of malicious intent.
- Do not attach third-party/private PCAPs, credentials, DNS hostnames, session tokens or unreviewed packet reports. Prefer minimal, synthetic fixtures generated locally.
- Do not claim detection precision, recall or universal protocol support without reproducible evidence.

## Local development

Install Python 3.10+ and TShark (Wireshark command-line dissector), then:

```bash
git clone https://github.com/sumair00190/TraceForge.git
cd TraceForge
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -q
python3 scripts/generate_demo_capture.py --scenario scan
traceforge demo/traceforge-scan-demo.pcap
```

While the repository is private, cloning requires collaborator access. Contributions can be submitted after the public release, if and when the owner makes the repository public.

## Pull request checklist

1. Describe the change, security assumptions and affected modules.
2. Add deterministic tests, including benign/edge cases. For protocol changes, include a safe TShark integration fixture where possible.
3. Confirm Python 3.10/3.13 tests and the GitHub Actions TShark smoke test.
4. Preserve report escaping, data minimization, offline operation and evidence frame references.
5. Update README, user documentation and limitations for any changed behavior.

Small bug fixes and documentation improvements are welcome. Do not add a dependency, active network probe, or external service without explaining its security/privacy impact.

## Licensing

The project is prepared for distribution under [Apache License 2.0](LICENSE). By submitting a contribution for inclusion, you agree that it may be distributed under the project's Apache-2.0 license and that you have the right to contribute the material. Retain existing copyright and attribution notices. Do not copy third-party code or test captures without appropriate permission and compatible licensing.

Security-sensitive reports should follow [SECURITY.md](SECURITY.md), not public issue discussions.
