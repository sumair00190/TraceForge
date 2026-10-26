# Configurable SYN Scan Sensitivity

TraceForge provides three **TCP SYN unique-destination-port** sensitivity profiles. These affect only the threshold-based SYN scan heuristic, not HTTP, DNS, TLS, ICMP, SMB2 or the capture inventory.

| Profile | Threshold | Tradeoff |
| --- | ---: | --- |
| `sensitive` | 5 unique ports | More candidate alerts, potentially more benign scanning flagged |
| `balanced` (default) | 10 unique ports | Existing v1.1 development default |
| `conservative` | 25 unique ports | Fewer candidate alerts, but smaller scans may be missed |

These numbers are **configurable heuristics, not validated confidence scores or proven attack detection accuracy**. An alert is not proof that scanning was unauthorized; absence of alerts is not proof a capture is safe.

## CLI example

```bash
traceforge demo/traceforge-scan-demo.pcap --profile sensitive
traceforge demo/traceforge-scan-demo.pcap --profile conservative
traceforge demo/traceforge-scan-demo.pcap --threshold 15
traceforge-batch demo/batch-validation --profile sensitive --output-dir reports/sensitive-batch
```

The 18-packet synthetic scan demo probes **13** ports: a sensitive/balanced scan will produce one review alert, while conservative (25 ports) will not. This comparison is intentionally synthetic, not a real-world accuracy benchmark.

## Optional JSON settings

Edit a local JSON file, such as `config/example.json`:

```json
{
  "profile": "conservative",
  "scan_threshold_unique_ports": 20,
  "batch_max_files": 10
}
```

All fields are optional. Supported fields:

- `profile`: `sensitive`, `balanced` or `conservative`.
- `scan_threshold_unique_ports`: integer **2–65535**. If set, overrides the JSON profile's threshold.
- `batch_max_files`: integer **1–10000** used only by `traceforge-batch`.

```bash
traceforge demo/traceforge-scan-demo.pcap --config config/example.json
traceforge-batch demo --config config/example.json --output-dir reports/from-config
```

Precedence (highest to lowest): **CLI `--threshold`**, CLI `--profile`, JSON threshold, JSON profile, default balanced.

Unknown fields, malformed JSON, values of the wrong type and files exceeding 16 KiB are rejected instead of silently ignored. Configuration processing stays local, and no scripts are executed.

Both JSON reports and the individual HTML report's provenance panel record the effective selection so findings can be reproduced. Batch JSON/HTML contains the effective threshold as well.

## Important scope limitations

Sensitivity profiles tune **only the number of unique ports** in the SYN heuristic; they are not general IDS signatures, behavior modeling, malware classification, or protocol decryption. For professional deployment, tune thresholds with authorized benign and attack-labeled captures and measure false positives/false negatives. For this initial version, continue manual investigation using the evidence frame numbers.
