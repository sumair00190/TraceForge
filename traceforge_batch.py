# Copyright 2026 sumair00190
# SPDX-License-Identifier: Apache-2.0
"""Offline batch investigation for authorized PCAP, PCAPNG, and CAP files.

The input captures are never changed. Every output path is deliberately unique,
and the combined summary does not include raw payloads or absolute paths.
"""
import argparse
from html import escape
import json
from pathlib import Path
import re
import sys

from traceforge import VERSION, analyze, capture_provenance, investigation_overview, render_html_report
from traceforge_config import PROFILE_THRESHOLDS, load_config, resolve_scan_settings, resolve_batch_limit

FORMATS = {".pcap", ".pcapng", ".cap"}


def discover_captures(directory, recursive=False):
    directory = Path(directory)
    if not directory.is_dir():
        raise ValueError("Input directory does not exist")
    iterator = directory.rglob("*") if recursive else directory.iterdir()
    captures = [
        path for path in iterator
        if path.is_file() and not path.is_symlink() and path.suffix.lower() in FORMATS
    ]
    return sorted(captures, key=lambda path: str(path.relative_to(directory)).casefold())


def safe_report_stem(path):
    """Avoid path traversal and unsafe output filenames."""
    return re.sub(r"[^a-zA-Z0-9 ._-]+", "_", path.stem).strip(" ._")[:65] or "capture"


def summarize_batch(rows, root):
    good = [row for row in rows if row["status"] == "ok"]
    return {
        "tool": "TraceForge",
        "version": VERSION,
        "mode": "batch",
        "input_directory": root.name,
        "files_discovered": len(rows),
        "analyzed": len(good),
        "failed": len(rows) - len(good),
        "total_packets": sum(row["packets"] for row in good),
        "total_review_findings": sum(row["review_findings"] for row in good),
        "captures": rows,
        "limitations": (
            "Separate forensic triage per capture. Counts are not deduplicated "
            "across captures; overlapping captures may double-count traffic. "
            "Findings are not proof of compromise; validation is required."
        ),
    }


def render_batch_html(summary):
    """Self-contained, escaped, read-only offline summary."""
    rows = []
    for item in summary["captures"]:
        title = escape(item["name"], quote=True)
        status = escape(item["status"].upper(), quote=True)
        packets = f'{item.get("packets", 0):,}' if item["status"] == "ok" else "—"
        review = str(item.get("review_findings", 0)) if item["status"] == "ok" else "—"
        if item["status"] == "ok" and item.get("report_html"):
            filename = escape(item["report_html"], quote=True)
            title = f'<a href="{filename}">{title}</a>'
        rows.append(
            f"<tr><td>{title}</td><td>{status}</td>"
            f"<td>{packets}</td><td>{review}</td></tr>"
        )
    body = "\n".join(rows) or '<tr><td colspan="4">No files</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>TraceForge | Batch Investigation</title>
<style>
:root {{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#081525;color:#edf5ff;font:15px/1.5 system-ui,sans-serif}}
main{{max-width:1080px;margin:auto;padding:42px 22px}}
.eyebrow{{color:#62d6ca;text-transform:uppercase;font-size:12px;letter-spacing:.15em}}
h1{{font-size:30px;margin:6px 0 12px}}p{{color:#abc1d5}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}}
.card,section{{background:#13253d;border:1px solid #2a4662;border-radius:11px;padding:16px}}
.card strong{{display:block;font-size:26px;color:#73e5d5}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:12px 8px;text-align:left;border-bottom:1px solid #29425d;overflow-wrap:anywhere}}
a{{color:#76dfd3}}a:hover{{color:white}}
.note{{border-left:4px solid #ecb96a;padding:9px 14px;background:#243146}}
@media(max-width:550px){{body{{font-size:13px}}main{{padding:18px 10px}}th,td{{padding:9px 4px}}}}
</style></head><body><main>
<div class="eyebrow">TraceForge v{escape(str(summary["version"]))} / Offline Network Investigation</div>
<h1>Batch Investigation Overview</h1>
<p>Input folder: {escape(summary["input_directory"], quote=True)} — analyst review required.</p>
<p>SYN profile: {escape(str(summary.get("detection_configuration", {}).get("profile", "Unknown")))}
 · Threshold: {escape(str(summary.get("detection_configuration", {}).get("scan_threshold_unique_ports", "Unknown")))}
 unique destination ports</p>
<div class="cards">
<div class="card">Discovered<strong>{summary["files_discovered"]}</strong></div>
<div class="card">Analyzed<strong>{summary["analyzed"]}</strong></div>
<div class="card">Failures<strong>{summary["failed"]}</strong></div>
<div class="card">Packets<strong>{summary["total_packets"]:,}</strong></div>
<div class="card">Review leads<strong>{summary["total_review_findings"]}</strong></div>
</div>
<section><h2>Capture reports</h2>
<table><thead><tr><th>Capture</th><th>Status</th><th>Packets</th><th>Review leads</th></tr></thead>
<tbody>{body}</tbody></table></section>
<p class="note">{escape(summary["limitations"], quote=True)}</p>
<p>Reports are local HTML + JSON files. No external scripts, styles or data uploads.</p>
</main></body></html>"""


def process_batch(directory, output_dir, threshold=10, fingerprint=False,
                  recursive=False, max_files=100, no_html=False, detection_settings=None):
    root, destination = Path(directory), Path(output_dir)
    if threshold < 2:
        raise ValueError("--threshold must be 2 or greater")
    if max_files < 1:
        raise ValueError("--max-files must be 1 or greater")
    captures = discover_captures(root, recursive=recursive)
    if not captures:
        raise ValueError("No .pcap, .pcapng, or .cap files found in the selected directory")
    if len(captures) > max_files:
        raise ValueError(f"Found {len(captures)} captures; increase --max-files to proceed")
    destination.mkdir(parents=True, exist_ok=True)

    rows = []
    for index, capture in enumerate(captures, 1):
        prefix = f"{index:04d}-{safe_report_stem(capture)}"
        record = {"name": capture.name, "status": "ok"}
        try:
            result = analyze(capture, threshold)
            result["detection_configuration"] = detection_settings or {
                "profile": "balanced",
                "scan_threshold_unique_ports": threshold,
                "threshold_source": "batch_argument",
            }
            result["capture_provenance"] = capture_provenance(
                capture, threshold, include_fingerprint=fingerprint
            )
            json_name = f"{prefix}-report.json"
            html_name = f"{prefix}-report.html"
            json_text = json.dumps(result, indent=2)
            html_text = render_html_report(result) if not no_html else None
            # Prepared before writing; writing failures are treated as per-file failures.
            (destination / json_name).write_text(json_text, encoding="utf-8")
            if html_text is not None:
                (destination / html_name).write_text(html_text, encoding="utf-8")
            record.update({
                "packets": result["total_packets"],
                "review_findings": investigation_overview(result)["review_count"],
                "report_json": json_name,
                "report_html": html_name if html_text is not None else None,
            })
        except (OSError, RuntimeError, ValueError) as error:
            record = {
                "name": capture.name,
                "status": "failed",
                "error": f"{type(error).__name__}: capture analysis or report writing failed",
            }
        rows.append(record)
        print(f"[{index}/{len(captures)}] {record['name']}: {record['status']}", flush=True)

    summary = summarize_batch(rows, root)
    summary["detection_configuration"] = detection_settings or {
        "profile": "balanced",
        "scan_threshold_unique_ports": threshold,
        "threshold_source": "batch_argument",
    }
    summary["max_files"] = max_files
    (destination / "batch-report.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if not no_html:
        (destination / "batch-report.html").write_text(render_batch_html(summary), encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description="TraceForge offline multi-capture investigation")
    parser.add_argument("directory", type=Path, help="folder of authorized capture files")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/batch"))
    parser.add_argument("--recursive", action="store_true", help="include subdirectories")
    parser.add_argument("--max-files", type=int, default=None,
                        help="maximum capture count (default 100, can be set in config)")
    parser.add_argument("--profile", choices=tuple(PROFILE_THRESHOLDS), default=None,
                        help="SYN sensitivity: sensitive=5, balanced=10, conservative=25")
    parser.add_argument("--config", type=Path, help="optional validated JSON configuration")
    parser.add_argument("--threshold", type=int, default=None,
                        help="override SYN scan threshold (2..65535)")
    parser.add_argument("--fingerprint", action="store_true", help="SHA-256 each file (extra read)")
    parser.add_argument("--no-html", action="store_true", help="save JSON summaries only")
    parser.add_argument("--version", action="version", version=f"TraceForge Batch {VERSION}")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        settings = resolve_scan_settings(config, args.profile, args.threshold)
        max_files = resolve_batch_limit(config, args.max_files)
        summary = process_batch(
            args.directory, args.output_dir, settings["scan_threshold_unique_ports"],
            args.fingerprint, args.recursive, max_files, args.no_html,
            detection_settings=settings,
        )
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(f"\nBatch: {summary['analyzed']}/{summary['files_discovered']} analyzed; "
          f"{summary['failed']} failed; {summary['total_review_findings']} heuristic leads.")
    print(f"JSON: {args.output_dir / 'batch-report.json'}")
    if not args.no_html:
        print(f"HTML: {args.output_dir / 'batch-report.html'}")
    if summary["failed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
