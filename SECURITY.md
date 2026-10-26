# Security Policy

TraceForge analyzes untrusted network capture files using TShark. Only analyze captures you are authorized to handle, and keep Wireshark/TShark updated.

## Reporting a vulnerability

**Do not disclose exploitable vulnerabilities, secrets, affected capture content, or private IP/user data in a public GitHub issue.**

To report a security issue privately, use GitHub's **Security → Report a vulnerability** option **if it is enabled** for this repository. If that option is unavailable, contact the project maintainer through a private contact method published on their verified GitHub profile before sending technical details. Never post credentials, sensitive PCAPs, or personal information.

Please include the affected version/commit, operating system, TShark version, a minimal non-sensitive reproduction, expected behavior, and actual behavior. Avoid testing systems or traffic without permission.

## Support expectations

This project is an educational, analyst-assistance tool and does not currently promise response times, coordinated-disclosure SLAs, or production-grade security guarantees. Fixes are handled as resources permit.

## Supported versions

The current development branch receives security fixes first. Tagged `v1.0` remains an earlier functional release and does not automatically include later fixes.

## Scope and limitations

- TraceForge performs local read-only analysis; it is not a real-time IDS.
- Reports may expose network metadata; inspect them before sharing.
- Encrypted or malformed captures and TShark vulnerabilities can limit safety and detection.
- Capture hashing is a file fingerprint, not forensic chain-of-custody certification.
