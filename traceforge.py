#!/usr/bin/env python3
# Copyright 2026 sumair00190
# SPDX-License-Identifier: Apache-2.0
"""TraceForge v1.1.0: offline, evidence-backed triage of authorized PCAP/PCAPNG.

Requires TShark. Does not export cookies, credentials, request bodies, or URL queries.
Network indicators are hypotheses for analyst review, not proof of compromise.
"""

import argparse
import hashlib
from collections import deque
from datetime import datetime, timezone
from html import escape as html_escape
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict, OrderedDict
from pathlib import Path
from traceforge_config import PROFILE_THRESHOLDS, load_config, resolve_scan_settings

VERSION = "1.1.0"
SCAN_FILTER = "tcp.flags.syn == 1 && tcp.flags.ack == 0"
HTTP_FILTER = "http.request || http.response"
DNS_FILTER = "dns && (dns.flags.response == 0 || dns.flags.response == 1)"
ICMP_FILTER = "icmp"
TLS_FILTER = "tls.handshake.type"
TLS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.stream", "tls.handshake.type", "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_server_name", "tls.handshake.ciphersuite",
]

# SMB2 share, command, and filename metadata only. No file contents or NTLM secrets.
SMB_FILTER = "smb2"
# Independent second pass: Wireshark may display a file association while
# -T fields on a compound SMB packet exposes only the first command/filename.
SMB_SERVICE_FILTER = 'smb2.filename contains "PSEXESVC.exe"'
SMB_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.stream", "smb2.cmd", "smb2.flags.response", "smb2.tree",
    "smb2.filename", "smb2.write.count",
]

ICMP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "icmp.type", "icmp.code", "icmp.ident", "icmp.seq",
]
DNS_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src",
    "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.flags.rcode",
]
HTTP_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src",
    "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
    "http.request.method", "http.request.uri", "http.user_agent",
    "http.response.code", "http.request_in",
]
SCANNER_MARKERS = ("gobuster", "ffuf", "feroxbuster", "dirbuster", "dirb", "wfuzz", "nikto")
MANAGER_PATH = "/manager/html"
MAX_PENDING_REQUESTS = 100_000

# Inventory classifies every captured packet independently of attack signatures.
# It never stores packet payloads, hostnames, DNS names, or arbitrary dissector text.
INVENTORY_FIELDS = [
    "frame.time_epoch", "frame.len", "frame.protocols", "ip.src",
    "ipv6.src", "ip.dst", "ipv6.dst", "tcp.dstport",
]
# First recognized higher-layer family wins; generic transport is a fallback.
PROTOCOL_PRIORITY = (
    ("HTTP/3", {"http3"}), ("HTTP/2", {"http2"}),
    ("HTTP", {"http"}), ("SMB2", {"smb2"}), ("SMB", {"smb"}),
    ("QUIC", {"quic"}), ("TLS", {"tls", "ssl"}),
    ("DNS", {"dns"}), ("mDNS", {"mdns"}), ("LLMNR", {"llmnr"}),
    ("DHCP", {"bootp", "dhcp", "dhcpv6"}),
    ("SSH", {"ssh"}), ("RDP", {"rdp"}), ("FTP", {"ftp"}),
    ("SMTP", {"smtp"}), ("IMAP", {"imap"}), ("POP3", {"pop"}),
    ("NTP", {"ntp"}), ("SNMP", {"snmp"}), ("SIP", {"sip"}),
    ("MQTT", {"mqtt"}), ("LDAP", {"ldap"}), ("Kerberos", {"kerberos"}),
    ("ICMPv6", {"icmpv6"}), ("ICMPv4", {"icmp"}),
    ("ARP", {"arp"}),
    ("UDP (other)", {"udp"}), ("TCP (other)", {"tcp"}),
    ("IPv6 (other)", {"ipv6"}), ("IPv4 (other)", {"ip"}),
)


def protocol_family(stack):
    """One primary decoded protocol family per packet (not a threat verdict)."""
    parts = set((stack or "").lower().split(":"))
    for label, names in PROTOCOL_PRIORITY:
        if parts.intersection(names):
            return label
    return "Other / undecoded"


def new_inventory():
    return {"families": Counter(), "total_wire_bytes": 0, "non_ip_packets": 0,
            "ipv6_packets": 0, "first_epoch": None, "last_epoch": None,
            "invalid_frame_lengths": 0}


def add_inventory_packet(inventory, timestamp, frame_length, stack, ipv4_src, ipv6_src):
    inventory["families"][protocol_family(stack)] += 1
    if not (ipv4_src or ipv6_src):
        inventory["non_ip_packets"] += 1
    if ipv6_src:
        inventory["ipv6_packets"] += 1
    try:
        length = int(frame_length)
        if 0 <= length <= 16_777_216:
            inventory["total_wire_bytes"] += length
        else:
            inventory["invalid_frame_lengths"] += 1
    except (ValueError, TypeError):
        inventory["invalid_frame_lengths"] += 1
    parsed_time = numeric_timestamp(timestamp)
    if parsed_time is not None and 0 <= parsed_time < 10**12:
        if inventory["first_epoch"] is None or parsed_time < inventory["first_epoch"]:
            inventory["first_epoch"] = parsed_time
        if inventory["last_epoch"] is None or parsed_time > inventory["last_epoch"]:
            inventory["last_epoch"] = parsed_time


def finish_inventory(inventory):
    """Small privacy-preserving report: traffic labels/counts only."""
    first, last = inventory["first_epoch"], inventory["last_epoch"]
    return {
        "primary_protocol_families": [
            {"name": name, "packets": count}
            for name, count in inventory["families"].most_common(24)
        ],
        "total_wire_bytes": inventory["total_wire_bytes"],
        "non_ip_packets": inventory["non_ip_packets"],
        "ipv6_packets": inventory["ipv6_packets"],
        "duration_seconds": round(max(0, last - first), 3) if first is not None and last is not None else None,
        "invalid_frame_lengths": inventory["invalid_frame_lengths"],
        "limitations": (
            "One primary protocol family per frame based on TShark dissectors; "
            "nested protocols are not all counted separately. Transport-only and "
            "Other/undecoded packets are still included. Visible protocol != decoded "
            "application content. No universal malicious-traffic detection is possible."
        ),
    }


def tshark_rows(capture, field_names, display_filter=None):
    """Yield fields streamed from TShark (never load entire capture into RAM)."""
    command = ["tshark", "-n", "-r", str(capture)]
    if display_filter:
        command.extend(["-Y", display_filter])
    command.extend(["-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"])
    for field in field_names:
        command.extend(["-e", field])

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr:
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=stderr,
                text=True, encoding="utf-8", errors="replace",
            )
        except FileNotFoundError as exc:
            raise RuntimeError("TShark not found. Install tshark and retry.") from exc
        assert process.stdout is not None
        try:
            for line in process.stdout:
                cells = line.rstrip("\r\n").split("\t")
                if len(cells) == len(field_names):
                    yield cells
        finally:
            process.stdout.close()
            return_code = process.wait()
        if return_code != 0:
            stderr.seek(0)
            raise RuntimeError(stderr.read().strip() or f"TShark failed: {return_code}")


def capture_provenance(capture, threshold, include_fingerprint=False):
    """Record reproducibility metadata without retaining packet content.

    SHA-256 is opt-in because hashing multi-GB files requires an additional
    full sequential read. It is an identifier, not a chain-of-custody guarantee.
    """
    capture = Path(capture)
    info = {
        "tool_version": VERSION,
        "capture_filename": capture.name,
        "capture_format": capture.suffix.lower().lstrip("."),
        "capture_bytes": capture.stat().st_size,
        "scan_threshold_unique_ports": threshold,
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "capture_sha256": None,
        "hashing_note": (
            "SHA-256 identifies file bytes at hashing time; it does not prove "
            "capture authenticity or forensic chain of custody."
        ),
    }
    if include_fingerprint:
        digest = hashlib.sha256()
        with capture.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        info["capture_sha256"] = digest.hexdigest()
    try:
        completed = subprocess.run(
            ["tshark", "--version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10, check=False,
        )
        first_line = (completed.stdout or "").splitlines()
        info["tshark_version"] = (
            first_line[0][:180] if completed.returncode == 0 and first_line
            else "Unavailable"
        )
    except (OSError, subprocess.TimeoutExpired):
        info["tshark_version"] = "Unavailable"
    return info


def numeric_timestamp(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def summarize_syn_probes(rows, threshold):
    groups = defaultdict(lambda: {"ports": set(), "frames": [], "count": 0, "first_ts": None, "probe_samples": []})
    for frame, timestamp, src4, src6, dst4, dst6, port in rows:
        src, dst = src4 or src6, dst4 or dst6
        if not src or not dst or not port:
            continue
        group = groups[(src, dst)]
        group["ports"].add(port)
        group["count"] += 1
        if group["first_ts"] is None:
            group["first_ts"] = numeric_timestamp(timestamp)
        if len(group["frames"]) < 5:
            group["frames"].append(frame)
        # Keep a bounded port/time/frame sample for later evidence correlation.
        if len(group["probe_samples"]) < 50:
            group["probe_samples"].append({
                "port": port, "frame": frame, "time_epoch": numeric_timestamp(timestamp)
            })
    candidates = []
    for (src, dst), group in groups.items():
        candidates.append({
            "source_ip": src,
            "destination_ip": dst,
            "unique_destination_ports": len(group["ports"]),
            "syn_probes": group["count"],
            "sample_destination_ports": sorted(group["ports"], key=lambda s: int(s) if s.isdigit() else 0)[:10],
            "sample_packet_numbers": group["frames"],
            "first_time_epoch": group["first_ts"],
            "sample_probes": group["probe_samples"],
            "alert": len(group["ports"]) >= threshold,
        })
    candidates.sort(key=lambda x: (x["unique_destination_ports"], x["syn_probes"]), reverse=True)
    return candidates


def safe_http_path(uri):
    """Drop query/fragments and known secret-bearing path components."""
    if not uri:
        return "/"
    stripped = uri.split("?", 1)[0].split("#", 1)[0]
    stripped = re.sub(r"(?i)(/(?:token|apikey|api_key|secret|session)/)[^/]+", r"\1[REDACTED]", stripped)
    return stripped[:160]


def append_frame(frames, frame):
    if frame and len(frames) < 6 and frame not in frames:
        frames.append(frame)


def scanner_identifiers(user_agent):
    """Return recognized scanner product/version only, not arbitrary User-Agent text."""
    if not user_agent:
        return []
    match = re.search(r"(?i)\b(gobuster|ffuf|feroxbuster|dirbuster|dirb|wfuzz|nikto)(?:/([0-9.]{1,24}))?\b", user_agent)
    if not match:
        return []
    return [match.group(1).lower() + ("/" + match.group(2) if match.group(2) else "")]


def timeline_event(event_type, timestamp, frame, src, dst, detail):
    return {
        "event": event_type,
        "time_epoch": timestamp,
        "sample_frame": frame,
        "source_ip": src,
        "destination_ip": dst,
        "summary": detail,
        "confidence": "heuristic_review_required",
    }


def analyze_http(rows, enumeration_threshold=20, auth_threshold=3):
    """Correlate TShark responses via http.request_in; no credential inspection.

    A Tomcat Manager HTTP 200 is a *candidate* only when the *same exact*
    /manager/html endpoint had a prior correlated 401 for that client/server.
    """
    flows = defaultdict(lambda: {
        "requests": 0, "paths": set(), "user_agents": Counter(),
        "scanner_frames": [], "scanner_first": None,
        "sample_request_frames": [], "failed_frames": [],
        "auth_failures": 0, "failure_first": None,
        "manager_failures": [], "manager_successes": [],
        "post_upload_candidates": [], "post_first": None,
    })
    requests_by_frame = OrderedDict()
    evicted_requests = 0
    response_codes = Counter()
    total_requests = total_responses = 0

    for (frame, time_epoch, src4, src6, dst4, dst6, sport, dport,
         method, uri, user_agent, status, request_in) in rows:
        src, dst = src4 or src6, dst4 or dst6
        time_value = numeric_timestamp(time_epoch)
        if method and src and dst:
            total_requests += 1
            key = (src, dst, dport or "unknown")
            item = flows[key]
            path = safe_http_path(uri)
            item["requests"] += 1
            if len(item["paths"]) < 1000:
                item["paths"].add(path)
            for tool in scanner_identifiers(user_agent):
                item["user_agents"][tool] += 1
                append_frame(item["scanner_frames"], frame)
                if item["scanner_first"] is None:
                    item["scanner_first"] = (time_value, frame)
            append_frame(item["sample_request_frames"], frame)
            if method.upper() == "POST" and any(marker in path.lower() for marker in ("/manager", "/upload", "/deploy")):
                append_frame(item["post_upload_candidates"], frame)
                if item["post_first"] is None:
                    item["post_first"] = (time_value, frame)
            if frame:
                # HTTP payload/cookies/auth headers are never extracted or stored.
                requests_by_frame[frame] = (key, path, time_value)
                if len(requests_by_frame) > MAX_PENDING_REQUESTS:
                    requests_by_frame.popitem(last=False)
                    evicted_requests += 1
        elif status:
            total_responses += 1
            response_codes[status] += 1
            if request_in and request_in in requests_by_frame:
                key, path, request_timestamp = requests_by_frame.pop(request_in)
                item = flows[key]
                manager_path = path.lower().rstrip("/") == MANAGER_PATH
                if status == "401":
                    item["auth_failures"] += 1
                    append_frame(item["failed_frames"], frame)
                    if item["failure_first"] is None:
                        item["failure_first"] = (time_value, frame)
                    if manager_path:
                        item["manager_failures"].append((time_value, frame))
                if status == "200" and manager_path:
                    # Require earlier correlated 401 for exact /manager/html.
                    prior_failures = [t for t, _ in item["manager_failures"]
                                      if t is not None and time_value is not None and t < time_value]
                    if prior_failures and len(item["manager_successes"]) < 6:
                        item["manager_successes"].append({
                            "path": path, "request_frame": request_in,
                            "response_frame": frame, "time_epoch": time_value,
                        })

    observations, timeline = [], []
    for (client, server, port), item in flows.items():
        paths = len(item["paths"])
        if item["scanner_frames"] or paths >= enumeration_threshold:
            observations.append({
                "type": "possible_http_directory_enumeration",
                "client_ip": client, "server_ip": server, "server_port": port,
                "requests": item["requests"], "unique_paths_at_least": paths,
                "scanner_user_agents": [tool for tool, _ in item["user_agents"].most_common(5)],
                "sample_packet_numbers": item["scanner_frames"] or item["sample_request_frames"],
                "assessment": "heuristic_not_proof",
            })
            candidate = item["scanner_first"]
            if candidate:
                timeline.append(timeline_event("directory_enumeration_candidate", candidate[0], candidate[1], client, server, "Scanner User-Agent observed"))
        if item["auth_failures"] >= auth_threshold:
            observations.append({
                "type": "repeated_http_401_responses",
                "client_ip": client, "server_ip": server, "server_port": port,
                "failures": item["auth_failures"],
                "sample_packet_numbers": item["failed_frames"],
                "assessment": "heuristic_not_proof",
            })
            candidate = item["failure_first"]
            if candidate:
                timeline.append(timeline_event("http_401_failures", candidate[0], candidate[1], server, client, "Repeated authentication failures (HTTP 401)"))
        if item["manager_successes"]:
            observations.append({
                "type": "possible_manager_access_after_401",
                "client_ip": client, "server_ip": server, "server_port": port,
                "manager_401_count": len(item["manager_failures"]),
                "admin_200_responses": item["manager_successes"],
                "assessment": "needs_manual_confirmation_of_authenticated_access",
            })
            successful = item["manager_successes"][0]
            timeline.append(timeline_event("manager_200_after_401_candidate", successful["time_epoch"], successful["response_frame"], server, client, "HTTP 200 on /manager/html after prior 401; verify response content"))
        if item["post_upload_candidates"]:
            observations.append({
                "type": "http_post_to_management_or_upload_path",
                "client_ip": client, "server_ip": server, "server_port": port,
                "sample_packet_numbers": item["post_upload_candidates"],
                "assessment": "post_is_not_proof_of_malicious_file_upload",
            })
            candidate = item["post_first"]
            if candidate:
                timeline.append(timeline_event("management_post_candidate", candidate[0], candidate[1], client, server, "HTTP POST to management/upload path; inspect content manually"))

    order = {
        "possible_http_directory_enumeration": 0,
        "repeated_http_401_responses": 1,
        "possible_manager_access_after_401": 2,
        "http_post_to_management_or_upload_path": 3,
    }
    observations.sort(key=lambda x: (order.get(x["type"], 9), x["client_ip"]))
    timeline.sort(key=lambda x: (x["time_epoch"] is None, x["time_epoch"] if x["time_epoch"] is not None else 0))
    return {
        "requests": total_requests, "responses": total_responses,
        "status_codes": dict(response_codes),
        "unmatched_evicted_requests": evicted_requests,
        "observations": observations[:100],
        "timeline": timeline[:100],
        "limitations": (
            "HTTP/1.x only where recognized by TShark; HTTPS payloads unreadable. "
            "200 on /manager/html after 401 is a candidate, not proof of auth. "
            "Incomplete captures or evicted unmatched requests can limit correlation. "
            "No credential, cookie, body or URL query string extraction."
        ),
    }



def analyze_dns(rows, long_label_threshold=48, burst_threshold=30):
    """Summarize DNS without recording queried domains in reports.

    Long DNS labels can be legitimate; findings are weak *review* signals.
    This deliberately does not declare DNS tunneling or C2.
    """
    queries = responses = 0
    qtypes = Counter()
    rcodes = Counter()
    by_client = Counter()
    long_label_events = defaultdict(lambda: {"count": 0, "frames": [], "first": None})
    for frame, epoch, src4, src6, response, name, qtype, rcode in rows:
        src = src4 or src6
        ts = numeric_timestamp(epoch)
        # Wireshark FT_BOOLEAN fields may be exported as False/True or 0/1.
        # Keep unrecognized/absent values out of either count.
        dns_response = str(response).strip().lower()
        if dns_response in {"0", "false", "unset", "no", "off"}:
            queries += 1
            if src:
                by_client[src] += 1
            if qtype:
                qtypes[qtype] += 1
            if src and name:
                labels = name.rstrip(".").split(".")
                # We examine names in memory but never export or print them.
                if any(len(label) >= long_label_threshold for label in labels):
                    item = long_label_events[src]
                    item["count"] += 1
                    append_frame(item["frames"], frame)
                    if item["first"] is None:
                        item["first"] = (ts, frame)
        elif dns_response in {"1", "true", "set", "yes", "on"}:
            responses += 1
            if rcode:
                rcodes[rcode] += 1
    findings = []
    timeline = []
    for client, item in long_label_events.items():
        # One unusual label is useful to review, not an asserted attack.
        finding = {
            "type": "dns_long_label_review", "client_ip": client,
            "count": item["count"], "sample_packet_numbers": item["frames"],
            "assessment": "weak_heuristic_may_be_legitimate",
        }
        findings.append(finding)
        first = item["first"]
        if first is not None:
            timeline.append(timeline_event(
                "dns_long_label_review", first[0], first[1],
                client, "DNS resolver (unspecified)",
                "Long DNS query label observed; benign DNS and DNS tunneling may look similar",
            ))
    for client, count in by_client.items():
        if count >= burst_threshold:
            findings.append({
                "type": "dns_high_query_count_review", "client_ip": client,
                "count": count, "sample_packet_numbers": [],
                "assessment": "no_time_window_or_baseline_weak_heuristic",
            })
    findings.sort(key=lambda x: (-x["count"], x["client_ip"]))
    return {
        "queries": queries, "responses": responses,
        "query_types": dict(qtypes), "response_rcodes": dict(rcodes),
        "top_query_clients": by_client.most_common(10),
        "observations": findings[:100], "timeline": timeline[:100],
        "limitations": "DNS query names intentionally omitted from reports. A long label or high count is not proof of tunneling or malware; TCP/DoH/DoT DNS may not decode.",
    }



def tls_version_name(raw):
    """Convert numeric TShark TLS versions, without confusing a legacy ClientHello version with negotiated TLS 1.3."""
    raw = str(raw).strip().lower()
    if not raw:
        return "unknown"
    try:
        value = int(raw, 0) if raw.startswith('0x') else int(raw)
    except ValueError:
        return "unknown"
    return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(value, "unknown")


def analyze_tls(rows):
    """Summarize *visible* TLS handshakes; never save SNI values, certificates or secrets.

    Values in ClientHello legacy_version are NOT evidence of the negotiated TLS version.
    A ServerHello supported_version extension (TLS 1.3) takes precedence.
    One frame may contain multiple handshake messages; with TShark occurrence=f
    only its first type is counted, so all counts are lower-bound observations.
    """
    counts = Counter()
    negotiated = Counter()
    samples = []
    weak_versions = []
    tls_clients = Counter()
    streams = set()
    visible_sni = 0
    sni_absent = 0
    for (frame, epoch, src4, src6, dst4, dst6, stream, handshake_type,
         hello_version, supported_version, sni_value, cipher_suite) in rows:
        typ = str(handshake_type).strip()
        if typ not in {"1", "2", "11"}:
            continue
        src, dst = src4 or src6, dst4 or dst6
        ts = numeric_timestamp(epoch)
        if stream:
            streams.add(str(stream))
        if typ == "1":
            counts["client_hello"] += 1
            tls_clients[src or "unknown"] += 1
            # Only the boolean is retained; SNI may be a sensitive hostname.
            if sni_value:
                visible_sni += 1
            else:
                sni_absent += 1
            if len(samples) < 10:
                samples.append({"frame": str(frame), "source_ip": src, "destination_ip": dst,
                                "sni_visible": bool(sni_value)})
        elif typ == "2":
            counts["server_hello"] += 1
            # In TLS 1.3 the ServerHello legacy_version is normally 0x0303.
            # Its selected supported_version extension is the authoritative version.
            chosen = tls_version_name(supported_version) if supported_version else tls_version_name(hello_version)
            negotiated[chosen] += 1
            if chosen in {"TLS 1.0", "TLS 1.1", "SSL 3.0"} and len(weak_versions) < 30:
                weak_versions.append({"frame": str(frame), "version": chosen,
                                      "source_ip": src, "destination_ip": dst, "time_epoch": ts})
        else:
            counts["certificate"] += 1
    timeline = [timeline_event(
        "legacy_tls_version_review", event["time_epoch"], event["frame"],
        event["source_ip"], event["destination_ip"],
        f"ServerHello suggests {event['version']} (validate handshake and endpoint configuration)",
    ) for event in weak_versions]
    return {
        "client_hello": counts["client_hello"],
        "server_hello": counts["server_hello"],
        "visible_certificate_messages": counts["certificate"],
        "tcp_streams_with_visible_handshakes": len(streams),
        "client_hellos_with_visible_sni": visible_sni,
        "client_hellos_without_visible_sni": sni_absent,
        "observed_server_hello_versions": dict(negotiated),
        "top_client_hello_sources": tls_clients.most_common(10),
        "sample_client_hellos": samples,
        "observations": [{"type": "legacy_tls_version_review", **v} for v in weak_versions],
        "timeline": timeline,
        "limitations": (
            "Only TShark-decoded TLS handshakes are counted. Encrypted ClientHello/ECH, missing handshake "
            "packets, QUIC, port-based misclassification and TLS 1.3 encrypted certificates can obscure data. "
            "TLS 1.3 uses legacy_version 0x0303: never interpret ClientHello legacy_version as negotiated TLS. "
            "Raw SNI hostnames, certificate contents and payloads are not saved."
        ),
    }


def analyze_icmp(rows, sweep_threshold=10, window_seconds=60, pending_limit=100_000):
    """Analyze ICMPv4 Echo traffic without extracting packet payloads.

    Match requests and replies using source/destination, identifier and sequence.
    A possible sweep needs multiple distinct targets within a time window; this
    remains a weak heuristic because network monitoring may do the same.
    """
    kinds = Counter()
    requests = replies = matched = 0
    by_source = Counter()
    targets = defaultdict(set)
    request_frames = defaultdict(list)
    windows = defaultdict(deque)
    pending = OrderedDict()
    pending_count = evicted_pending = 0
    findings = []
    timeline = []
    flagged_sources = set()

    for frame, epoch, src, dst, kind, code, identifier, seq in rows:
        if not src or not dst or not kind:
            continue
        timestamp = numeric_timestamp(epoch)
        typ = str(kind).strip()
        kinds[typ] += 1
        key = (src, dst, identifier, seq)
        if typ == "8" and str(code).strip() == "0":
            requests += 1
            by_source[src] += 1
            targets[src].add(dst)
            append_frame(request_frames[src], frame)
            # ICMP identifier+sequence may be absent. Do not falsely correlate
            # packets unless both fields are available.
            if identifier and seq:
                if key not in pending:
                    pending[key] = deque()
                pending[key].append(frame)
                pending_count += 1
                while pending_count > pending_limit and pending:
                    _, evicted = pending.popitem(last=False)
                    evicted_pending += len(evicted)
                    pending_count -= len(evicted)
            if timestamp is not None:
                window = windows[src]
                # Some PCAPs are not timestamp-sorted. Reset rather than
                # accidentally claiming a time-bounded sweep.
                if window and timestamp < window[-1][0]:
                    window.clear()
                window.append((timestamp, dst, frame))
                while window and timestamp - window[0][0] > window_seconds:
                    window.popleft()
                unique = {destination for _, destination, _ in window}
                if len(unique) >= sweep_threshold and src not in flagged_sources:
                    flagged_sources.add(src)
                    frames = [f for _, _, f in list(window)[:6]]
                    findings.append({
                        "type": "possible_icmp_echo_sweep", "source_ip": src,
                        "distinct_destinations_in_window": len(unique),
                        "window_seconds": window_seconds,
                        "sample_packet_numbers": frames,
                        "assessment": "weak_heuristic_review_required",
                    })
                    timeline.append(timeline_event(
                        "icmp_echo_sweep_candidate", timestamp, frame, src,
                        "multiple destinations", f"Echo requests to {len(unique)} destinations within {window_seconds}s; verify context"
                    ))
        elif typ == "0" and str(code).strip() == "0":
            replies += 1
            reverse = (dst, src, identifier, seq)
            if identifier and seq and reverse in pending and pending[reverse]:
                pending[reverse].popleft()
                matched += 1
                pending_count -= 1
                if not pending[reverse]:
                    del pending[reverse]

    return {
        "echo_requests": requests, "echo_replies": replies,
        "matched_replies": matched,
        "requests_without_matching_reply": max(0, requests - matched),
        "unmatched_replies": max(0, replies - matched),
        "evicted_pending_requests": evicted_pending,
        "icmp_type_counts": dict(kinds),
        "top_ping_sources": [
            {"source_ip": ip, "requests": count, "distinct_destinations": len(targets[ip]),
             "sample_packet_numbers": request_frames[ip]}
            for ip, count in by_source.most_common(10)
        ],
        "observations": findings[:100], "timeline": timeline[:100],
        "limitations": (
            "ICMPv4 Echo only; ICMPv6 not yet supported. Missing capture packets, "
            "identifier/sequence fields or truncated captures affect reply matching. "
            "Unmatched Echo Requests are not proof that a host is down. "
            "Possible ping sweeps are weak heuristic indicators, not confirmed attacks."
        ),
    }


def _smb2_command(value):
    """TShark usually emits decimal command IDs; also accept hexadecimal."""
    try:
        text = str(value).strip()
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except (ValueError, TypeError):
        return None


def _share_label(raw):
    """Classify common shares, without saving server/hostnames or arbitrary paths."""
    # The Tree Connect request normally holds \\server\share.
    bits = str(raw or "").replace("/", "\\").rstrip("\\").split("\\")
    share = bits[-1].upper().strip() if bits else ""
    if share in {"ADMIN$", "IPC$"}:
        return share
    if len(share) == 2 and share[0] in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" and share[1] == "$":
        return "DRIVE_ADMIN_SHARE"
    return None


def _is_psexec_service_executable(raw):
    """Recognize PsExec's known service basename; never export arbitrary filenames."""
    basename = str(raw or "").replace("/", "\\").split("\\")[-1].casefold()
    return basename == "psexesvc.exe"


def analyze_smb(rows):
    """Bounded, read-only SMB2 metadata triage; no usernames, hashes or files saved.

    Only a PSEXESVC.exe Create request plus a subsequent same-stream Write
    justifies the stronger *transfer candidate* wording. Share use alone and
    the presence of PsExec are not proof of unauthorized lateral movement.
    """
    packets = requests = 0
    cmd_counts = Counter()
    pairs = {}
    for (frame, epoch, src4, src6, dst4, dst6, stream,
         command, response, tree, filename, write_count) in rows:
        if not frame or not str(frame).isdigit():
            continue
        packets += 1
        if _flag_value(response):
            continue
        requests += 1
        src, dst = src4 or src6, dst4 or dst6
        cmd = _smb2_command(command)
        if cmd is None or not src or not dst:
            continue
        cmd_counts[str(cmd)] += 1
        pair = pairs.setdefault((src, dst), {
            "source_ip": src, "destination_ip": dst, "requests": 0,
            "share_types": set(), "sample_packet_numbers": [],
            "service": {}, "first_time_epoch": numeric_timestamp(epoch),
        })
        pair["requests"] += 1
        if cmd == 3:  # Tree Connect Request
            share = _share_label(tree)
            if share:
                pair["share_types"].add(share)
                append_frame(pair["sample_packet_numbers"], frame)
        if not stream or cmd not in (5, 9):
            continue
        if cmd == 5 and _is_psexec_service_executable(filename):
            svc = pair["service"].setdefault(stream, {
                "create_frame": frame, "create_time_epoch": numeric_timestamp(epoch),
                "write_frames": [], "explicit_write_frames": [],
                "explicit_write_count": 0,
            })
        elif cmd == 9 and stream in pair["service"]:
            svc = pair["service"][stream]
            # Frames are processed in capture order. Avoid linking a Write for
            # an unrelated file unless TShark associates it with PSEXESVC.exe.
            if _is_psexec_service_executable(filename):
                svc["explicit_write_count"] += 1
                append_frame(svc["explicit_write_frames"], frame)
            elif not filename:
                append_frame(svc["write_frames"], frame)
    observations, timeline, pairs_out = [], [], []
    for pair in pairs.values():
        svc_records = []
        for stream, entry in pair["service"].items():
            if not entry["create_frame"]:
                continue
            explicit = entry["explicit_write_frames"]
            frames = [entry["create_frame"]] + explicit[:5]
            svc_records.append({
                "tcp_stream": str(stream),
                "create_frame": entry["create_frame"],
                "sample_packet_numbers": frames,
                "explicit_write_requests": entry["explicit_write_count"],
                "write_requests_without_filename": len(entry["write_frames"]),
                "first_time_epoch": entry["create_time_epoch"],
            })
            if len(observations) < 100:
                assessment = "explicit_file_create_and_write" if entry["explicit_write_count"] else "file_create_only_verify_write"
                evidence = frames[:6]
                observation = {
                    "type": "psexec_service_file_candidate",
                    "source_ip": pair["source_ip"],
                    "destination_ip": pair["destination_ip"],
                    "tcp_stream": str(stream),
                    "service_executable": "PSEXESVC.exe",
                    "assessment": assessment,
                    "sample_packet_numbers": evidence,
                    "share_context": sorted(pair["share_types"]),
                    "explicit_write_requests": entry["explicit_write_count"],
                }
                observations.append(observation)
                timeline.append(timeline_event(
                    "smb_psexec_service_file_candidate", entry["create_time_epoch"],
                    entry["create_frame"], pair["source_ip"], pair["destination_ip"],
                    "PsExec service executable Create request; verify file transfer and authorization",
                ))
        if len(pairs_out) < 50:
            pairs_out.append({
                "source_ip": pair["source_ip"], "destination_ip": pair["destination_ip"],
                "requests": pair["requests"], "administrative_shares": sorted(pair["share_types"]),
                "sample_packet_numbers": pair["sample_packet_numbers"],
                "psexec_streams": svc_records[:10],
            })
    pairs_out.sort(key=lambda p: p["requests"], reverse=True)
    return {
        "decoded_packets": packets, "requests": requests,
        "request_command_counts": dict(cmd_counts),
        "top_pairs": pairs_out, "observations": observations, "timeline": timeline,
        "limitations": (
            "SMB2 only where TShark recognizes unencrypted metadata. SMB3 encryption, incomplete "
            "captures, compound messages, field decoding differences and missing Write filenames limit correlation. "
            "PsExec file artifacts and administrative shares also occur in legitimate administration; "
            "nothing here proves a malicious actor or successful service execution. "
            "No credentials, NTLM hashes, arbitrary file paths, server names or file contents are exported."
        ),
    }


def supplement_smb_service_evidence(summary, filtered_rows):
    """Reconcile TShark-filtered PsExec filename evidence with SMB metadata.

    TShark may include a filename in its display-filter evaluation while
    emitting a blank or different first occurrence in -T fields (especially
    compounded SMB2 messages). The separate server-side filter is narrower
    than the general SMB parser; it is NOT a proof of execution or compromise.
    Only recognized PsExec service-file activity is added to the report.
    """
    groups = {}
    for row in filtered_rows:
        if len(row) != len(SMB_FIELDS):
            continue
        (frame, epoch, src4, src6, dst4, dst6, stream,
         cmd_raw, is_response, tree, filename, write_count) = row
        if not frame or not str(frame).isdigit() or _flag_value(is_response):
            continue
        src, dst = src4 or src6, dst4 or dst6
        if not src or not dst:
            continue
        key = (src, dst, str(stream or 'unknown'))
        entry = groups.setdefault(key, {"frames": [], "create_frames": [],
                                       "write_frames": [], "first_epoch": numeric_timestamp(epoch)})
        append_frame(entry["frames"], frame)
        cmd = _smb2_command(cmd_raw)
        if cmd == 5:
            append_frame(entry["create_frames"], frame)
        elif cmd == 9:
            append_frame(entry["write_frames"], frame)

    existing = {(ob.get("source_ip"), ob.get("destination_ip"), str(ob.get("tcp_stream")))
                for ob in summary.get("observations", [])}
    share_map = {(p["source_ip"], p["destination_ip"]): p["administrative_shares"]
                 for p in summary.get("top_pairs", [])}
    for (src, dst, stream), entry in groups.items():
        if (src, dst, stream) in existing or not entry["frames"]:
            continue
        if len(summary["observations"]) >= 100:
            break
        # If first occurrence fields are unavailable, fall back to a *review*
        # candidate based on TShark's explicit file-name display filter.
        strong = bool(entry["create_frames"] and entry["write_frames"])
        assessment = ("explicit_file_create_and_write" if strong else
                      "filename_filtered_activity_verify_create_and_write")
        summary["observations"].append({
            "type": "psexec_service_file_candidate",
            "source_ip": src, "destination_ip": dst,
            "tcp_stream": stream, "service_executable": "PSEXESVC.exe",
            "assessment": assessment,
            "sample_packet_numbers": entry["frames"][:6],
            "share_context": share_map.get((src, dst), []),
            "explicit_write_requests": len(entry["write_frames"]),
        })
        first_frame = (entry["create_frames"] or entry["frames"])[0]
        summary["timeline"].append(timeline_event(
            "smb_psexec_service_file_candidate", entry["first_epoch"],
            first_frame, src, dst,
            "PsExec service filename observed in SMB2; verify Create/Write and authorization",
        ))
    return summary


def correlate_outbound_syn(scans, http):
    """Look for SYNs from a scanned server back to the scanner after HTTP POST.

    These are investigation candidates, not evidence proving a reverse shell.
    All comparison timestamps are PCAP-relative epoch times.
    """
    scanned_pairs = {(c["source_ip"], c["destination_ip"])
                     for c in scans if c["alert"]}
    post_events = [ev for ev in http["timeline"]
                   if ev["event"] == "management_post_candidate"
                   and ev["time_epoch"] is not None]
    observations = []
    timeline = []
    for ev in post_events:
        client, server, ts = ev["source_ip"], ev["destination_ip"], ev["time_epoch"]
        if (client, server) not in scanned_pairs:
            continue
        for scan in scans:
            if scan["source_ip"] != server or scan["destination_ip"] != client:
                continue
            following = [probe for probe in scan.get("sample_probes", [])
                         if probe["time_epoch"] is not None and probe["time_epoch"] > ts]
            if not following:
                continue
            ports = sorted({p["port"] for p in following}, key=lambda x: int(x) if x.isdigit() else 0)
            frames = [p["frame"] for p in following[:6]]
            first = min(following, key=lambda p: p["time_epoch"])
            observations.append({
                "type": "outbound_syn_after_management_post",
                "source_ip": server, "destination_ip": client,
                "ports": ports[:20], "syn_probe_count_sampled": len(following),
                "sample_packet_numbers": frames,
                "linked_post_frame": ev["sample_frame"],
                "assessment": "temporal_correlation_only_not_proof_of_callback",
            })
            timeline.append(timeline_event(
                "outbound_syn_after_management_post_candidate", first["time_epoch"],
                first["frame"], server, client,
                "Outbound SYN to previous scanner after management POST; ports " + ", ".join(ports[:8]),
            ))
    return {"observations": observations[:50], "timeline": timeline[:50]}




def _syn_candidate_frames(observations):
    """Return only evidence frame numbers; no payload inspection needed."""
    frames = set()
    for observation in observations[:50]:
        for value in observation.get("sample_packet_numbers", [])[:6]:
            if str(value).isdigit():
                frames.add(str(value))
    return sorted(frames, key=int)[:250]


def _flag_value(text):
    """Accept TShark boolean fields including 0x00/0x01 representations."""
    value = str(text or "").strip().lower()
    if value in {"true", "set", "yes", "on"}:
        return True
    try:
        return int(value, 0) != 0
    except ValueError:
        return False


def _packet_info(values):
    (frame, epoch, src4, src6, dst4, dst6, sport, dport,
     stream, syn, ack, length, flags) = values
    # Using the numeric TCP flags when available avoids differences in FT_BOOLEAN
    # presentation across versions of TShark.
    bits = None
    try:
        bits = int(flags, 0)
    except (TypeError, ValueError):
        pass
    return {
        "frame": frame, "source": src4 or src6, "destination": dst4 or dst6,
        "source_port": sport, "destination_port": dport, "stream": stream,
        "syn": bool(bits & 0x02) if bits is not None else _flag_value(syn),
        "ack": bool(bits & 0x10) if bits is not None else _flag_value(ack),
        "data_length": int(length) if length.isdigit() else 0,
    }


def summarize_outbound_stream_packets(seeds, rows):
    """Correlate already-selected outbound SYN streams with packet metadata.

    Seeds are records (observation index, stream ID, port, initial frame, source, dest).
    No TCP contents, credentials or DNS names enter the report.
    """
    streams = {}
    for index, stream, port, frame, server, remote in seeds:
        streams[(index, stream)] = {
            "destination_port": port, "tcp_stream": stream,
            "syn_frame": frame, "syn_ack_observed": False,
            "packets": 0, "outbound_payload_bytes": 0,
            "inbound_payload_bytes": 0, "sample_packet_numbers": [],
            "_source": server, "_remote": remote,
        }
    for values in rows:
        packet = _packet_info(values)
        for (_, stream), item in streams.items():
            if packet["stream"] != stream:
                continue
            src, dst = packet["source"], packet["destination"]
            server, remote = item["_source"], item["_remote"]
            if not ((src == server and dst == remote) or (src == remote and dst == server)):
                continue
            item["packets"] += 1
            append_frame(item["sample_packet_numbers"], packet["frame"])
            if src == server and dst == remote:
                item["outbound_payload_bytes"] += packet["data_length"]
            elif src == remote and dst == server:
                item["inbound_payload_bytes"] += packet["data_length"]
                if packet["syn"] and packet["ack"]:
                    item["syn_ack_observed"] = True
    result = defaultdict(list)
    for (index, _), item in streams.items():
        item.pop("_source")
        item.pop("_remote")
        result[index].append(item)
    for connections in result.values():
        connections.sort(key=lambda d: (int(d["destination_port"]) if d["destination_port"].isdigit() else 0, int(d["syn_frame"])))
    return dict(result)


def enrich_outbound_connections(capture, observations):
    """Inspect flow metadata for each flagged outbound SYN using TCP stream IDs."""
    for item in observations:
        item["connections"] = []
    selected = _syn_candidate_frames(observations)
    if not selected:
        return
    fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.flags.syn", "tcp.flags.ack", "tcp.len", "tcp.flags",
    ]
    display = " || ".join(f"frame.number == {frame}" for frame in selected)
    frame_to_observations = defaultdict(list)
    for i, item in enumerate(observations[:50]):
        for frame in item.get("sample_packet_numbers", [])[:6]:
            frame_to_observations[str(frame)].append(i)
    seeds, known = [], set()
    for values in tshark_rows(capture, fields, display):
        packet = _packet_info(values)
        # The frame numbers already came from SCAN_FILTER (SYN=1, ACK=0);
        # avoid dropping legitimate SYN frames when TShark renders flags as 'Set'.
        if not packet["stream"]:
            continue
        for index in frame_to_observations.get(packet["frame"], []):
            observation = observations[index]
            if (packet["source"] != observation["source_ip"] or
                    packet["destination"] != observation["destination_ip"] or
                    packet["destination_port"] not in observation["ports"]):
                continue
            key = (index, packet["stream"])
            if key not in known:
                seeds.append((index, packet["stream"], packet["destination_port"],
                              packet["frame"], packet["source"], packet["destination"]))
                known.add(key)
    if not seeds:
        return
    unique_streams = sorted({seed[1] for seed in seeds}, key=int)
    stream_filter = " || ".join(f"tcp.stream == {num}" for num in unique_streams)
    by_observation = summarize_outbound_stream_packets(seeds, tshark_rows(capture, fields, stream_filter))
    for index, connections in by_observation.items():
        observations[index]["connections"] = connections


def analyze(capture, threshold):
    sources, ports = Counter(), Counter()
    total = ip_total = 0
    inventory = new_inventory()
    for epoch, wire_len, stack, src4, src6, dst4, dst6, tcpport in tshark_rows(
        capture, INVENTORY_FIELDS
    ):
        add_inventory_packet(inventory, epoch, wire_len, stack, src4, src6)
        total += 1
        src, dst = src4 or src6, dst4 or dst6
        if src and dst:
            ip_total += 1
            sources[src] += 1
            if tcpport:
                ports[tcpport] += 1
    syn_fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ipv6.src",
        "ip.dst", "ipv6.dst", "tcp.dstport",
    ]
    scans = summarize_syn_probes(tshark_rows(capture, syn_fields, SCAN_FILTER), threshold)
    http = analyze_http(tshark_rows(capture, HTTP_FIELDS, HTTP_FILTER))
    dns = analyze_dns(tshark_rows(capture, DNS_FIELDS, DNS_FILTER))
    icmp = analyze_icmp(tshark_rows(capture, ICMP_FIELDS, ICMP_FILTER))
    tls = analyze_tls(tshark_rows(capture, TLS_FIELDS, TLS_FILTER))
    smb = analyze_smb(tshark_rows(capture, SMB_FIELDS, SMB_FILTER))
    # A second narrow query compensates for compounds/field-occurrence gaps.
    # It stores only recognized service name and bounded frame/stream evidence.
    smb = supplement_smb_service_evidence(
        smb, tshark_rows(capture, SMB_FIELDS, SMB_SERVICE_FILTER))
    outbound = correlate_outbound_syn(scans, http)
    enrich_outbound_connections(capture, outbound["observations"])
    scan_alerts = [dict(row, type="possible_tcp_syn_port_scan", assessment="heuristic_not_proof")
                   for row in scans if row["alert"]]
    timeline = list(http["timeline"]) + list(dns["timeline"]) + list(icmp["timeline"]) + list(tls["timeline"]) + list(smb["timeline"]) + list(outbound["timeline"])
    for scan in scans:
        if scan["alert"]:
            timeline.append(timeline_event(
                "tcp_syn_port_scan_candidate", scan["first_time_epoch"],
                scan["sample_packet_numbers"][0], scan["source_ip"],
                scan["destination_ip"], f"{scan['unique_destination_ports']} destination ports probed",
            ))
    timeline.sort(key=lambda x: (x["time_epoch"] is None, x["time_epoch"] if x["time_epoch"] is not None else 0))
    return {
        "tool": "TraceForge", "version": VERSION, "capture": capture.name,
        "total_packets": total, "ip_packets": ip_total,
        "top_source_ips": sources.most_common(10),
        "top_tcp_destination_ports": ports.most_common(10),
        "capture_inventory": finish_inventory(inventory),
        "scan_threshold_unique_ports": threshold,
        "scan_candidates": scans[:30],
        "alerts": scan_alerts,
        "http_analysis": http,
        "dns_analysis": dns,
        "icmp_analysis": icmp,
        "tls_analysis": tls,
        "smb_analysis": smb,
        "outbound_correlations": outbound["observations"],
        "timeline": timeline[:100],
        "limitations": (
            "Read-only offline triage. Findings require analyst validation. "
            "Encrypted, truncated, fragmented or unsupported traffic may be missed."
        ),
    }



def html_text(value):
    """Safely display any packet-derived value as untrusted text."""
    return html_escape(str(value), quote=True)


def evidence_numbers(item):
    """Keep frame references limited and numeric, not arbitrary HTML."""
    frames = item.get("sample_packet_numbers", [])
    if not frames and item.get("admin_200_responses"):
        frames = [candidate.get("response_frame", "") for candidate in item["admin_200_responses"]]
    return [str(frame) for frame in frames[:6] if str(frame).isdigit()]


def format_utc(timestamp):
    try:
        if timestamp is None:
            return "Timestamp unavailable"
        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError, OverflowError, OSError):
        return "Timestamp unavailable"


def display_number(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError, OverflowError):
        return str(value)


def investigation_overview(result):
    """Count supported review leads without assigning unsupported severity or risk scores."""
    http = result.get("http_analysis") or {}
    dns = result.get("dns_analysis") or {}
    icmp = result.get("icmp_analysis") or {}
    tls = result.get("tls_analysis") or {}
    smb = result.get("smb_analysis") or {}
    categories = [
        ("TCP SYN scan", result.get("alerts") or []),
        ("HTTP", http.get("observations") or []),
        ("DNS", dns.get("observations") or []),
        ("ICMP Echo sweep", icmp.get("observations") or []),
        ("TLS version", tls.get("observations") or []),
        ("SMB2 / PsExec", smb.get("observations") or []),
        ("Outbound correlation", result.get("outbound_correlations") or []),
    ]
    groups = []
    for label, items in categories:
        if not items:
            continue
        first = items[0]
        frames = evidence_numbers(first) if isinstance(first, dict) else []
        groups.append({"label": label, "count": len(items),
                       "first_evidence_frame": frames[0] if frames else None})
    return {
        "review_count": sum(group["count"] for group in groups),
        "categories": groups,
        "note": "Heuristic observations only; validate in Wireshark. No findings does not imply safe traffic.",
    }


def render_html_report(result):
    """Standalone, print-friendly report; escapes all values and loads no remote assets."""
    def e(value):
        return html_text(value)

    def tile(label, value, supporting):
        return (f'<div class="metric"><span class="metric-label">{e(label)}</span>'
                f'<strong>{e(value)}</strong><small>{e(supporting)}</small></div>')

    def row(*cells):
        return "<tr>" + "".join(f"<td>{e(cell)}</td>" for cell in cells) + "</tr>"

    def label_tag(value, style="muted"):
        return f'<span class="tag {style}">{e(value)}</span>'

    scan_count = len(result.get("alerts", []))
    http = result.get("http_analysis", {})
    observations = http.get("observations", [])
    timeline = result.get("timeline", [])
    dns = result.get("dns_analysis", {})
    icmp = result.get("icmp_analysis", {})
    tls = result.get("tls_analysis", {})
    smb = result.get("smb_analysis", {})
    outbound = result.get("outbound_correlations", [])
    inventory = result.get("capture_inventory", {})
    config = result.get("detection_configuration", {})
    provenance = result.get("capture_provenance", {})
    overview = investigation_overview(result)
    overview_cards = []
    for group in overview["categories"]:
        frame_label = (
            "First sample frame: " + e(group["first_evidence_frame"])
            if group["first_evidence_frame"] else "Sample frame unavailable"
        )
        overview_cards.append(
            '<article class="overview-item"><span class="overview-title">'
            + e(group["label"]) + '</span><strong>'
            + e(group["count"]) + '</strong><small>' + frame_label + '</small></article>'
        )
    if not overview_cards:
        overview_cards.append('<p class="empty">No supported heuristic review findings in this capture. This is not proof of safe traffic.</p>')
    overview_html = "".join(overview_cards)
    proto_rows = []
    for info in inventory.get("primary_protocol_families", [])[:12]:
        packet_count = int(info.get("packets", 0))
        total_packets = max(1, int(result.get("total_packets", 0)))
        portion = min(100, max(0, round(100 * packet_count / total_packets)))
        proto_rows.append(
            '<div class="protocol-row"><span class="protocol-name">' + e(info.get("name", "Other"))
            + '</span><div class="protocol-track"><div class="protocol-fill" style="width:'
            + str(portion) + '%"></div></div><span class="protocol-value">'
            + e(display_number(packet_count)) + '</span></div>'
        )
    if not proto_rows:
        proto_rows = ['<p class="empty">No decodable packet families to display.</p>']
    duration = inventory.get("duration_seconds")
    duration_text = f"{duration:,.2f} sec" if isinstance(duration, (float, int)) else "Unavailable"
    inventory_note = e(inventory.get("limitations", "Protocol recognition depends on capture and dissectors."))
    metrics = "".join([
        tile("Packets decoded", f"{result.get('total_packets', 0):,}", "From the selected capture"),
        tile("Capture duration", duration_text, "First to last timestamp"),
        tile("SYN scan alerts", scan_count, "Threshold-based candidates"),
        tile("HTTP requests", http.get("requests", 0), "HTTP recognized by TShark"),
        tile("HTTP review findings", len(observations), "Investigate before concluding"),
        tile("DNS queries", dns.get("queries", 0), "DNS where decoded by TShark"),
        tile("ICMP Echo Requests", icmp.get("echo_requests", 0), "ICMPv4 requests in capture"),
        tile("TLS ClientHellos", tls.get("client_hello", 0), "Visible TLS handshakes only"),
        tile("SMB2 requests", smb.get("requests", 0), "Decoded SMB2 request packets"),
        tile("Outbound follow-ups", len(outbound), "Correlations, not confirmed callbacks"),
    ])

    smb_summary = (
        f"Decoded SMB2 packets: <b>{e(smb.get('decoded_packets', 0))}</b>; "
        f"SMB2 requests: <b>{e(smb.get('requests', 0))}</b>; "
        f"PsExec service file candidates: <b>{e(len(smb.get('observations', [])))}</b>."
    )
    smb_cards = []
    for obs in smb.get("observations", [])[:20]:
        frames = ", ".join(e(x) for x in evidence_numbers(obs)) or "Unavailable"
        smb_cards.append(
            '<article class="finding"><div class="finding-head"><h3>PsExec service executable — review</h3>'
            + label_tag("REVIEW", "review") + '</div>'
            + f'<p>{e(obs.get("source_ip", "?"))} &rarr; {e(obs.get("destination_ip", "?"))}'
            + f'; TCP stream {e(obs.get("tcp_stream", "?"))}</p>'
            + f'<p>Recognized executable: {e(obs.get("service_executable", "PSEXESVC.exe"))}; '
            + f'explicit Write frames: {e(obs.get("explicit_write_requests", 0))}.</p>'
            + f'<p class="evidence">Evidence frames: {frames}</p></article>'
        )
    if not smb_cards:
        smb_cards.append('<p class="empty">No PsExec service-file candidates decoded. Not proof of no lateral movement.</p>')
    smb_pairs = []
    for pair in smb.get("top_pairs", [])[:10]:
        names = ", ".join(pair.get("administrative_shares", [])) or "No known administrative share decoded"
        frames = ", ".join(e(x) for x in evidence_numbers(pair)) or "Unavailable"
        smb_pairs.append(
            '<article class="finding"><h3>' + e(pair.get("source_ip", "?")) + ' &rarr; '
            + e(pair.get("destination_ip", "?")) + '</h3>'
            + f'<p>{e(pair.get("requests", 0))} requests; shares: {e(names)}</p>'
            + f'<p class="evidence">Share evidence frames: {frames}</p></article>'
        )
    if not smb_pairs:
        smb_pairs.append('<p class="empty">No SMB2 request flows decoded.</p>')

    source_rows = "".join(row(ip, f"{count:,}") for ip, count in result.get("top_source_ips", [])[:10])
    if not source_rows:
        source_rows = '<tr><td colspan="2">No IP source information available.</td></tr>'

    scan_cards = []
    for candidate in result.get("scan_candidates", [])[:20]:
        active = candidate.get("alert", False)
        status = label_tag("SCAN CANDIDATE" if active else "Below threshold", "alert" if active else "muted")
        frames = ", ".join(e(f) for f in evidence_numbers(candidate)) or "Unavailable"
        scan_cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><h3>{e(candidate.get("source_ip", "?"))} '
            f'&rarr; {e(candidate.get("destination_ip", "?"))}</h3>{status}</div>'
            f'<p><b>{e(display_number(candidate.get("unique_destination_ports", 0)))}</b> unique destination ports; '
            f'<b>{e(display_number(candidate.get("syn_probes", 0)))}</b> SYN probes.</p>'
            f'<p class="evidence">Evidence frames: {frames}</p>'
            '</article>'
        )
    if not scan_cards:
        scan_cards.append('<p class="empty">No SYN probes decoded. This is not proof that traffic is safe.</p>')

    friendly_types = {
        "possible_http_directory_enumeration": "Possible directory enumeration",
        "repeated_http_401_responses": "Repeated HTTP authentication failures",
        "possible_manager_access_after_401": "Possible manager access following HTTP 401s",
        "http_post_to_management_or_upload_path": "POST to management/upload endpoint",
    }
    http_cards = []
    for observation in observations[:50]:
        typ = observation.get("type", "HTTP observation")
        details = []
        if observation.get("scanner_user_agents"):
            details.append("Scanner: " + ", ".join(map(str, observation["scanner_user_agents"][:5])))
        if "failures" in observation:
            details.append("HTTP 401 responses: " + str(observation["failures"]))
        if observation.get("admin_200_responses"):
            first = observation["admin_200_responses"][0]
            details.append("HTTP 200 response on " + str(first.get("path", "unknown")) + " (verification required)")
        frames = ", ".join(e(f) for f in evidence_numbers(observation)) or "Unavailable"
        info = " | ".join(e(d) for d in details) or "Requires manual verification"
        http_cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><h3>{e(friendly_types.get(typ, typ))}</h3>'
            f'{label_tag("REVIEW", "review")}</div>'
            f'<p>{e(observation.get("client_ip", "?"))} &rarr; '
            f'{e(observation.get("server_ip", "?"))}:{e(observation.get("server_port", "?"))}</p>'
            f'<p>{info}</p><p class="evidence">Evidence frames: {frames}</p>'
            '</article>'
        )
    if not http_cards:
        http_cards.append('<p class="empty">No HTTP observations were flagged.</p>')

    dns_cards = []
    for obs in dns.get("observations", [])[:20]:
        reason = ("Long query labels" if obs.get("type") == "dns_long_label_review" else
                  "High DNS query count (no time window baseline)")
        frames = ", ".join(e(f) for f in evidence_numbers(obs)) or "Unavailable"
        dns_cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><h3>{e(reason)}</h3>{label_tag("REVIEW", "review")}</div>'
            f'<p>Client: {e(obs.get("client_ip", "?"))}; events: {e(obs.get("count", 0))}</p>'
            f'<p class="evidence">Evidence frames: {frames}</p>'
            '</article>'
        )
    if not dns_cards:
        dns_cards.append('<p class="empty">No DNS heuristics flagged. This does not imply DNS is safe.</p>')
    icmp_cards = []
    for source in icmp.get("top_ping_sources", [])[:10]:
        frames = ", ".join(e(f) for f in evidence_numbers(source)) or "Unavailable"
        icmp_cards.append(
            '<article class="finding">'
            f'<h3>{e(source.get("source_ip", "?"))}</h3>'
            f'<p>Echo Requests: {e(source.get("requests", 0))}; '
            f'distinct destinations: {e(source.get("distinct_destinations", 0))}</p>'
            f'<p class="evidence">Sample frames: {frames}</p></article>'
        )
    if not icmp_cards:
        icmp_cards.append('<p class="empty">No ICMPv4 Echo Requests decoded.</p>')
    icmp_findings = []
    for observation in icmp.get("observations", [])[:20]:
        frames = ", ".join(e(f) for f in evidence_numbers(observation)) or "Unavailable"
        icmp_findings.append(
            '<article class="finding">'
            f'<div class="finding-head"><h3>Possible ICMP Echo sweep</h3>{label_tag("REVIEW", "review")}</div>'
            f'<p>{e(observation.get("source_ip", "?"))}: '
            f'{e(observation.get("distinct_destinations_in_window", 0))} targets in '
            f'{e(observation.get("window_seconds", 0))} seconds</p>'
            f'<p class="evidence">Evidence frames: {frames}</p></article>'
        )
    if not icmp_findings:
        icmp_findings.append('<p class="empty">No ICMP Echo sweep heuristics flagged.</p>')
    icmp_summary = (
        f'<p>Requests: <b>{e(icmp.get("echo_requests", 0))}</b>; '
        f'Replies: <b>{e(icmp.get("echo_replies", 0))}</b>; '
        f'Matched replies: <b>{e(icmp.get("matched_replies", 0))}</b>; '
        f'Unmatched requests: <b>{e(icmp.get("requests_without_matching_reply", 0))}</b> '
        '(capture-limited, not proof of unreachable hosts).</p>'
    )
    tls_cards = []
    for version, count in sorted(tls.get("observed_server_hello_versions", {}).items()):
        tls_cards.append(
            '<article class="finding"><h3>' + e(version) + '</h3>'
            + '<p>ServerHello observations: ' + e(count) + '</p></article>'
        )
    if not tls_cards:
        tls_cards.append('<p class="empty">No ServerHello versions decoded; TLS might be absent or handshake missing.</p>')
    for finding in tls.get("observations", [])[:10]:
        tls_cards.append('<article class="finding">'
            + '<div class="finding-head"><h3>Legacy TLS version — review</h3>'
            + label_tag("REVIEW", "review") + '</div><p>'
            + e(finding.get("version", "")) + ' seen in ServerHello</p>'
            + '<p class="evidence">Frame: ' + e(finding.get("frame", "")) + '</p></article>')
    tls_summary = (
        '<p>ClientHello: <b>' + e(tls.get("client_hello", 0))
        + '</b>; ServerHello: <b>' + e(tls.get("server_hello", 0))
        + '</b>; visible certificate messages: <b>' + e(tls.get("visible_certificate_messages", 0))
        + '</b>.</p><p>ClientHellos with visible SNI: <b>'
        + e(tls.get("client_hellos_with_visible_sni", 0))
        + '</b>. Hostnames are intentionally omitted.</p>'
    )
    outbound_cards = []
    for obs in outbound[:20]:
        ports = ", ".join(e(port) for port in obs.get("ports", []))
        frames = ", ".join(e(f) for f in evidence_numbers(obs)) or "Unavailable"
        connection_rows = []
        for conn in obs.get("connections", [])[:20]:
            hs = "SYN-ACK observed" if conn.get("syn_ack_observed") else "SYN-ACK not captured"
            connection_rows.append(
                f'<p>Port {e(conn.get("destination_port", "?"))}, '
                f'TCP stream {e(conn.get("tcp_stream", "?"))}: {e(hs)}; '
                f'payload bytes out/in '
                f'{e(conn.get("outbound_payload_bytes", 0))}/'
                f'{e(conn.get("inbound_payload_bytes", 0))}</p>'
            )
        if not connection_rows:
            connection_rows.append('<p class="empty">Stream details unavailable; validate SYN frames in TShark.</p>')
        outbound_cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><h3>Outbound SYN after management POST</h3>{label_tag("REVIEW", "review")}</div>'
            f'<p>{e(obs.get("source_ip", "?"))} &rarr; {e(obs.get("destination_ip", "?"))} '
            f'(ports: {ports})</p>'
            f'<p class="evidence">Evidence frames: {frames}; linked HTTP POST frame: '
            f'{e(obs.get("linked_post_frame", "?"))}</p>'
            + ''.join(connection_rows)
            + '</article>'
        )
    if not outbound_cards:
        outbound_cards.append('<p class="empty">No outbound POST-follow-up candidates found. Not proof of safety.</p>')

    timeline_cards = []
    for event in timeline[:100]:
        frame = str(event.get("sample_frame", ""))
        safe_frame = e(frame) if frame.isdigit() else "Unavailable"
        timeline_cards.append(
            '<li class="event">'
            f'<div class="event-time">{e(format_utc(event.get("time_epoch")))} | Frame {safe_frame}</div>'
            f'<h3>{e(event.get("event", "Observation"))}</h3>'
            f'<p>{e(event.get("summary", ""))}</p>'
            f'<p class="event-route">{e(event.get("source_ip", "?"))} &rarr; '
            f'{e(event.get("destination_ip", "?"))}</p>'
            '</li>'
        )
    if not timeline_cards:
        timeline_cards.append('<li class="empty">No timeline candidates detected.</li>')

    status_rows = "".join(row(code, count) for code, count in sorted(http.get("status_codes", {}).items()))
    if not status_rows:
        status_rows = '<tr><td colspan="2">No HTTP responses decoded.</td></tr>'
    title = e(result.get("capture", "capture"))
    limitation = e(result.get("limitations", "Findings require analyst review."))
    http_limitation = e(http.get("limitations", ""))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>TraceForge | {title}</title>
<style>
:root {{ color-scheme:dark; --bg:#091321; --panel:#122239; --ink:#ecf5ff; --muted:#9eb3ca; --line:#2c425d; --accent:#50d7cc; --warning:#f4b85d; }}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--ink); font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif; margin:0; }}
header {{ background:#07101e; color:#fff; padding:40px max(22px,calc((100vw - 1050px)/2)); }}
header .eyebrow {{ color:#71e0d5; text-transform:uppercase; font-size:12px; letter-spacing:.16em; font-weight:750; }}
header h1 {{ font-size:34px; margin:7px 0; }}
header p {{ color:#b9cde5; margin:0; }}
main {{ max-width:1100px; padding:25px 24px 70px; margin:auto; }}
h2 {{ font-size:21px; margin:30px 0 12px; }}
h3 {{ font-size:15px; margin:0 0 6px; overflow-wrap:anywhere; }}
p {{ margin:5px 0 9px; overflow-wrap:anywhere; }}
.note {{ background:#263044; border-left:4px solid #f4b85d; padding:12px 15px; border-radius:7px; margin:18px 0; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-top:0; }}
.metric,.panel,.finding {{ background:var(--panel); border:1px solid var(--line); border-radius:11px; padding:16px; }}
.metric strong {{ font-size:24px; display:block; margin:5px 0 0; }}
.metric-label,.metric small {{ display:block; color:var(--muted); }}
.metric-label {{ font-size:12px; font-weight:700; text-transform:uppercase; }}
.metric small {{ font-size:11px; }}
.protocol-row {{ display:grid; grid-template-columns:120px minmax(0,1fr) 80px; gap:13px; align-items:center; margin:12px 0; }}
.protocol-name {{ font-size:13px; font-weight:650; }}
.protocol-value {{ text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); font-size:13px; }}
.protocol-track {{ height:9px; border-radius:30px; overflow:hidden; background:#2c4059; }}
.protocol-fill {{ height:100%; background:linear-gradient(90deg,#2d93b6,#5ce0c4); border-radius:30px; }}
.fingerprint {{ overflow-wrap:anywhere;word-break:break-all;font-family:ui-monospace,monospace;font-size:12px; }}
.overview-top {{ display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:12px; }}
.overview-total {{ font-size:30px;font-weight:750;color:var(--accent); }}
.overview-list {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px; }}
.overview-item {{ background:#192d46;border:1px solid var(--line);padding:12px;border-radius:8px; }}
.overview-title,.overview-item small {{ display:block; }}
.overview-title {{ color:var(--muted);font-size:12px; }}
.overview-item strong {{ display:block;font-size:22px;margin:3px 0; }}
.overview-item small {{ color:var(--muted);font-size:12px; }}
.two-col {{ display:grid;grid-template-columns:1fr 1fr; gap:16px; }}
.finding {{ margin-bottom:10px; }}
.finding-head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:8px; }}
.tag {{ white-space:nowrap; font-weight:700; font-size:10px; letter-spacing:.05em; border-radius:20px; padding:4px 9px; }}
.tag.alert {{ background:#4a252c; color:#ffc5b4; }}
.tag.review {{ background:#473a24; color:#ffe0a4; }}
.tag.muted {{ background:#25394e; color:#bed3e7; }}
.evidence,.event-time,.event-route {{ font-size:12px; color:var(--muted); }}
.event-time {{ font-weight:650; }}
.timeline {{ border-left:2px solid #347b83; padding:0 0 0 25px; list-style:none; margin:0 0 0 10px; }}
.event {{ position:relative; background:var(--panel); padding:12px 14px; margin:0 0 13px; border-radius:8px; border:1px solid var(--line); }}
.event:before {{ position:absolute; content:""; width:10px; height:10px; background:var(--accent); border-radius:50%; left:-32px; top:18px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ color:var(--muted);text-align:left; font-size:12px; }}
th,td {{ padding:7px 8px; border-bottom:1px solid var(--line); overflow-wrap:anywhere; }}
.empty {{ color:var(--muted); font-style:italic; }}
footer {{ color:var(--muted); font-size:12px; margin-top:30px; }}
@media(max-width:780px) {{ .metrics {{ grid-template-columns:1fr 1fr; }} .two-col {{ grid-template-columns:1fr; }} }}
@media(max-width:440px) {{ .metrics {{ grid-template-columns:1fr; }} header h1 {{font-size:27px;}} .protocol-row {{ grid-template-columns:90px minmax(0,1fr) 55px; gap:6px; }} }}
@media print {{ :root {{ color-scheme:light; --bg:white; --panel:white; --ink:#172336; --muted:#465568; --line:#cad6e0; }} body {{ background:white; }} header {{ color:#172336; background:white; border-bottom:2px solid #13273d; padding:15px 0; }} header p,header .eyebrow {{ color:#172336; }} main {{ padding:10px 0; }} .metric,.panel,.finding,.event {{ break-inside:avoid; }} }}
</style>
</head>
<body>
<header><div class="eyebrow">TraceForge v{e(result.get('version', VERSION))} / Offline Network Investigation</div>
<h1>Evidence-led Traffic Analysis</h1><p>Capture: {title} &nbsp; | &nbsp; PCAP / PCAPNG &nbsp; | &nbsp; Analyst review required</p></header>
<main>
<div class="note"><b>Interpretation note:</b> Findings represent automated hypotheses for investigation, not confirmed attacks or proof of compromise. Encrypted or missing network traffic may limit detection.</div>
<div class="metrics">{metrics}</div>
<h2>Investigation at a glance</h2>
<section class="panel" aria-label="Investigation overview">
<div class="overview-top"><div><b>Supported heuristic review findings</b>
<p class="evidence">{e(overview["note"])}</p></div>
<span class="overview-total">{e(overview["review_count"])}</span></div>
<div class="overview-list">{overview_html}</div></section>
<h2>Capture provenance</h2>
<section class="panel">
<p><b>File:</b> {e(provenance.get("capture_filename", result.get("capture", "Unavailable")))}</p>
<p><b>File size:</b> {e(display_number(provenance.get("capture_bytes", 0)))} bytes</p>
<p><b>Analyzed at (UTC):</b> {e(provenance.get("analyzed_at_utc", "Unavailable"))}</p>
<p><b>TShark build:</b> {e(provenance.get("tshark_version", "Unavailable"))}</p>
<p><b>SYN sensitivity profile:</b> {e(config.get("profile", "Not recorded"))}</p>
<p><b>Threshold selected by:</b> {e(config.get("threshold_source", "Not recorded"))}</p>
<p><b>Scan alert threshold:</b> {e(provenance.get("scan_threshold_unique_ports", "Unavailable"))} unique destination ports</p>
<p><b>Capture SHA-256:</b> <span class="fingerprint">{e(provenance.get("capture_sha256") or "Not calculated — rerun with --fingerprint")}</span></p>
<p class="evidence">{e(provenance.get("hashing_note", "Fingerprint identifies file bytes, not chain of custody."))}</p>
</section>
<h2>Capture-wide Protocol Landscape</h2>
<div class="two-col"><section class="panel"><h3>Primary decoded protocol families</h3>
{''.join(proto_rows)}
<p class="evidence">Protocol categories are mutually exclusive. Counts sum to total captured packets (unless only top families are shown).</p></section>
<section class="panel"><h3>Capture coverage</h3>
<p>Bytes on wire: <b>{e(display_number(inventory.get('total_wire_bytes', 0)))}</b></p>
<p>IPv6 packets: <b>{e(display_number(inventory.get('ipv6_packets', 0)))}</b></p>
<p>Non-IP packets: <b>{e(display_number(inventory.get('non_ip_packets', 0)))}</b></p>
<p>Capture time span: <b>{e(duration_text)}</b></p>
<p class="evidence">{inventory_note}</p>
<p class="evidence">This overview works even when no supported attack heuristic matches.</p></section></div>
<h2>Investigation Timeline</h2><ol class="timeline">{''.join(timeline_cards)}</ol>
<h2>Detection Findings</h2>
<div class="two-col"><section><h3>TCP SYN scan analysis</h3>{''.join(scan_cards)}</section>
<section><h3>HTTP triage</h3>{''.join(http_cards)}</section></div>
<h2>DNS &amp; Outbound Correlation</h2>
<div class="two-col"><section><h3>DNS review signals</h3>{''.join(dns_cards)}</section>
<section><h3>Outbound follow-up candidates</h3>{''.join(outbound_cards)}</section></div>
<h2>ICMP Echo Investigation</h2>
<div class="panel">{icmp_summary}</div>
<div class="two-col"><section><h3>Top ping sources</h3>{''.join(icmp_cards)}</section>
<section><h3>ICMP sweep candidates</h3>{''.join(icmp_findings)}</section></div>
<h2>TLS Handshake Investigation</h2>
<div class="panel">{tls_summary}</div>
<section>{''.join(tls_cards)}</section>
<h2>SMB2 / PsExec Investigation</h2>
<div class="panel">{smb_summary}</div>
<div class="two-col"><section><h3>Service-file evidence</h3>{''.join(smb_cards)}</section>
<section><h3>SMB2 client/server flows</h3>{''.join(smb_pairs)}</section></div>
<h2>Traffic Overview</h2>
<div class="two-col"><section class="panel"><h3>Top source IPs</h3><table><thead><tr><th>Source</th><th>Packets</th></tr></thead><tbody>{source_rows}</tbody></table></section>
<section class="panel"><h3>HTTP response codes</h3><table><thead><tr><th>HTTP status</th><th>Responses</th></tr></thead><tbody>{status_rows}</tbody></table></section></div>
<h2>Limitations &amp; Safe Handling</h2><div class="panel"><p>{limitation}</p><p>{http_limitation}</p><p>{e(dns.get("limitations", ""))}</p><p>{e(icmp.get("limitations", ""))}</p><p>{e(tls.get("limitations", ""))}</p><p>{e(smb.get("limitations", ""))}</p><p>Reports omit HTTP bodies, authorization headers, cookies and URL query strings. Do not treat unknown external IPs or HTTP status codes as malicious without corroboration.</p></div>
<footer>Generated locally with TraceForge. No external JavaScript, CSS, fonts or network calls. Packet/frame numbers can be checked manually in Wireshark using <code>frame.number == NUMBER</code>.</footer>
</main></body></html>"""


def main():
    parser = argparse.ArgumentParser(description=f"TraceForge v{VERSION} offline PCAP/PCAPNG analyzer")
    parser.add_argument("capture", type=Path, nargs="?", help="authorized .pcap or .pcapng file")
    parser.add_argument("--version", action="version", version=f"TraceForge {VERSION}")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"),
                        help="directory for reports (default: ./reports)")
    parser.add_argument("--no-html", action="store_true",
                        help="save JSON only (skip HTML report)")
    parser.add_argument("--profile", choices=tuple(PROFILE_THRESHOLDS), default=None,
                        help="SYN sensitivity: sensitive=5, balanced=10, conservative=25 unique ports")
    parser.add_argument("--config", type=Path, help="optional validated JSON profile configuration")
    parser.add_argument("--threshold", type=int, default=None,
                        help="override SYN scan threshold (2..65535), takes precedence over profile")
    parser.add_argument("--fingerprint", action="store_true",
                        help="include optional SHA-256 capture fingerprint (additional full file read)")
    args = parser.parse_args()
    if args.capture is None:
        parser.error("capture file is required")
    if args.capture.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        parser.error("expected a .pcap, .pcapng or .cap file")
    if not args.capture.is_file():
        parser.error(f"Capture not found: {args.capture}")
    try:
        settings = resolve_scan_settings(load_config(args.config), args.profile, args.threshold)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.threshold = settings["scan_threshold_unique_ports"]
    try:
        result = analyze(args.capture, args.threshold)
        result["detection_configuration"] = settings
        result["capture_provenance"] = capture_provenance(
            args.capture, args.threshold, include_fingerprint=args.fingerprint,
        )
    except (OSError, RuntimeError) as exc:
        sys.exit(f"Error: {exc}")

    print(f"\n=== TraceForge v{VERSION} ===")
    print(f"Capture: {result['capture']}")
    print(f"Packets: {result['total_packets']:,} (IP: {result['ip_packets']:,})")
    provenance = result.get("capture_provenance", {})
    if provenance.get("capture_sha256"):
        print(f"Capture SHA-256: {provenance['capture_sha256']}")
    print(f"TShark: {provenance.get('tshark_version', 'Unavailable')}")
    print(f"SYN sensitivity: {settings['profile']} | threshold: {args.threshold} ports ({settings['threshold_source']})")
    inventory = result.get("capture_inventory", {})
    print("\nCapture-wide protocol inventory (one primary family per packet):")
    for item in inventory.get("primary_protocol_families", [])[:10]:
        print(f"  {item['name']}: {item['packets']:,} packets")
    print(f"  Non-IP packets: {inventory.get('non_ip_packets', 0):,}; "
          f"IPv6 packets: {inventory.get('ipv6_packets', 0):,}")
    print("\nTop source IPs:")
    for ip, count in result["top_source_ips"][:5]:
        print(f"  {ip}: {count:,} packets")
    print("\nPort scan candidates:")
    if not result["scan_candidates"]:
        print("  No decoded SYN probes.")
    for item in result["scan_candidates"][:5]:
        label = "ALERT" if item["alert"] else "below threshold"
        print(f"  [{label}] {item['source_ip']} -> {item['destination_ip']}: "
              f"{item['unique_destination_ports']} unique ports, {item['syn_probes']} SYN probes")
        print("    Evidence frames: " + ", ".join(item["sample_packet_numbers"]))
    print(f"\nPossible port scan alerts: {len(result['alerts'])}")

    http = result["http_analysis"]
    print(f"\nHTTP analysis: {http['requests']} requests, {http['responses']} responses")
    print("Response codes: " + (
        ", ".join(f"{code}: {count}" for code, count in sorted(http["status_codes"].items())) or "none"
    ))
    if not http["observations"]:
        print("  No HTTP heuristic observations (not proof of safety).")
    for obs in http["observations"][:12]:
        print(f"  [REVIEW] {obs['type']}: {obs['client_ip']} -> {obs['server_ip']}:{obs['server_port']}")
        if "scanner_user_agents" in obs:
            print("    Scanner User-Agent: " + (", ".join(obs["scanner_user_agents"]) or "not identified"))
        if "failures" in obs:
            print(f"    HTTP 401 responses: {obs['failures']}")
        frames = obs.get("sample_packet_numbers")
        if frames:
            print("    Evidence frames: " + ", ".join(frames))
        if "admin_200_responses" in obs:
            evidence = obs["admin_200_responses"][0]
            print(f"    Candidate Manager HTTP 200: {evidence['path']} (response frame {evidence['response_frame']})")
    print(f"\nDNS analysis: {result['dns_analysis']['queries']} queries, {result['dns_analysis']['responses']} responses")
    print(f"DNS review observations: {len(result['dns_analysis']['observations'])}")
    icmp = result["icmp_analysis"]
    print(f"\nICMP analysis: {icmp['echo_requests']} Echo Requests, {icmp['echo_replies']} Echo Replies")
    print(f"  Matched replies: {icmp['matched_replies']}")
    print(f"  Requests without matched reply: {icmp['requests_without_matching_reply']} (not proof of host failure)")
    for source in icmp["top_ping_sources"][:5]:
        print(f"  {source['source_ip']}: {source['requests']} requests to {source['distinct_destinations']} unique destinations")
    print(f"Possible ICMP sweep candidates: {len(icmp['observations'])}")
    tls = result["tls_analysis"]
    print(f"\nTLS analysis: {tls['client_hello']} ClientHello, {tls['server_hello']} ServerHello, "
          f"{tls['visible_certificate_messages']} visible certificate handshake messages")
    print(f"  ClientHellos with visible SNI: {tls['client_hellos_with_visible_sni']} (hostnames omitted)")
    print("  Observed ServerHello versions: " + (
        ", ".join(f"{name}: {count}" for name, count in sorted(tls['observed_server_hello_versions'].items()))
        or "none"
    ))
    print(f"  Legacy TLS version review findings: {len(tls['observations'])}")
    smb = result["smb_analysis"]
    print(f"\nSMB2 analysis: {smb['decoded_packets']} decoded packets, {smb['requests']} requests")
    print(f"  PsExec service-file candidates: {len(smb['observations'])}")
    for obs in smb["observations"][:10]:
        print(f"  [REVIEW] {obs['source_ip']} -> {obs['destination_ip']} | "
              f"stream {obs['tcp_stream']} | {obs['service_executable']} | "
              f"explicit Writes: {obs['explicit_write_requests']}")
        print("    Evidence frames: " + ", ".join(obs["sample_packet_numbers"]))
    for pair in smb["top_pairs"][:5]:
        if pair["administrative_shares"]:
            print(f"  Shares: {pair['source_ip']} -> {pair['destination_ip']}: "
                  + ", ".join(pair["administrative_shares"]))
    print("\nOutbound POST follow-up candidates (not confirmed callbacks):")
    if not result["outbound_correlations"]:
        print("  None; not proof that traffic is safe.")
    for observation in result["outbound_correlations"][:10]:
        print(f"  [REVIEW] {observation['source_ip']} -> {observation['destination_ip']} "
              f"ports: {', '.join(observation['ports'])}")
        print("    Evidence frames: " + ", ".join(observation["sample_packet_numbers"]))
        if not observation.get("connections"):
            print("    TCP stream details unavailable; check source SYN frames in TShark.")
        for conn in observation.get("connections", []):
            handshake = "SYN-ACK observed" if conn["syn_ack_observed"] else "no SYN-ACK captured"
            print(f"    Port {conn['destination_port']} | TCP stream {conn['tcp_stream']} | {handshake} "
                  f"| payload bytes out/in: {conn['outbound_payload_bytes']}/{conn['inbound_payload_bytes']}")
    print("\nAttack investigation timeline (candidates, not confirmed exploitation):")
    if not result["timeline"]:
        print("  No timeline candidates found.")
    for ev in result["timeline"][:12]:
        print(f"  frame {ev['sample_frame']}: {ev['event']} — {ev['summary']}")

    # Restrict report filename to a predictable length and portable characters.
    safe_stem = re.sub(r"[^a-zA-Z0-9 ._-]+", "_", args.capture.stem).strip(" ._")[:100] or "capture"
    output = args.output_dir / f"{safe_stem}-report.json"
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nJSON report: {output}")
        if not args.no_html:
            html_output = output.with_suffix(".html")
            html_output.write_text(render_html_report(result), encoding="utf-8")
            print(f"HTML report: {html_output}")
    except OSError as exc:
        sys.exit(f"Could not save report: {exc}")
    print()


if __name__ == "__main__":
    main()
