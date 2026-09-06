"""Read-only PCAP adapter using tshark field export.

The adapter extracts headers and observable handshake metadata only. It never
follows streams, decrypts sessions, or sends packets.
"""

from __future__ import annotations

import ipaddress
import json
import math
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FIELDS = (
    "frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
    "dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.flags.rcode",
    "dns.count.answers", "tls.handshake.type", "tls.handshake.ja3",
    "tls.handshake.ja3s", "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str", "tls.record.length",
)


def _first(value: str) -> str:
    return value.split(",", 1)[0] if value else ""


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def _dns_name_features(name: str) -> dict[str, Any]:
    compact = name.rstrip(".")
    characters = compact.lower()
    counts = {char: characters.count(char) for char in set(characters)}
    total = len(characters)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values()) if total else 0.0
    return {
        "query_name": name, "query_length": len(compact), "label_count": len(compact.split(".")) if compact else 0,
        "max_label_length": max((len(label) for label in compact.split(".")), default=0),
        "name_entropy": entropy, "digit_ratio": sum(char.isdigit() for char in characters) / total if total else 0.0,
        "unique_char_ratio": len(set(characters)) / total if total else 0.0,
    }


def _row_to_dict(line: str) -> dict[str, str] | None:
    values = line.rstrip("\n").split("\t")
    if len(values) != len(FIELDS) or not values[0] or not values[2] or not values[3]:
        return None
    return dict(zip(FIELDS, values))


def _run_tshark(pcap: Path) -> list[dict[str, str]]:
    if shutil.which("tshark") is None:
        raise RuntimeError("tshark is required for direct PCAP extraction")
    command = ["tshark", "-r", str(pcap), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(("-e", field))
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return [row for line in result.stdout.splitlines() if (row := _row_to_dict(line)) is not None]


def extract_pcap(pcap: Path, run_id: str) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """Return normalized flows plus DNS/TLS metadata indexed by generated flow ID."""
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in _run_tshark(pcap):
        protocol = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(row["ip.proto"], row["ip.proto"])
        source_port = _first(row["tcp.srcport"] or row["udp.srcport"])
        destination_port = _first(row["tcp.dstport"] or row["udp.dstport"])
        grouped[(row["ip.src"], row["ip.dst"], source_port, destination_port, protocol)].append(row)

    flows: list[dict[str, Any]] = []
    dns_by_flow: dict[str, list[dict[str, Any]]] = defaultdict(list)
    encrypted_by_flow: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for number, (key, rows) in enumerate(sorted(grouped.items()), 1):
        source, destination, source_port, destination_port, protocol = key
        times = [float(row["frame.time_epoch"]) for row in rows]
        sizes = [int(float(row["frame.len"])) for row in rows if row["frame.len"]]
        flow_id = f"{run_id}-{number:08d}"
        flow = {
            "run_id": run_id, "flow_id": flow_id, "capture_host": "pve-capture",
            "capture_interface": None, "source_file": pcap.name, "exporter_source": "pcap",
            "record_version": "1.0", "start_time": _iso(min(times)), "end_time": _iso(max(times)),
            "duration_ms": int((max(times) - min(times)) * 1000), "src_ip": source, "dst_ip": destination,
            "src_port": int(source_port) if source_port else None, "dst_port": int(destination_port) if destination_port else None,
            "protocol": protocol, "ip_version": ipaddress.ip_address(source).version,
            "src_is_internal": source.startswith("10.10.1."), "dst_is_internal": destination.startswith("10.10.1."),
            "packets": len(rows), "bytes": sum(sizes), "packet_sizes": sizes, "packet_times": times,
            "syn_count": sum(_first(row["tcp.flags.syn"]) == "1" for row in rows),
            "syn_ack_count": sum(_first(row["tcp.flags.syn"]) == "1" and _first(row["tcp.flags.ack"]) == "1" for row in rows),
            "ack_count": sum(_first(row["tcp.flags.ack"]) == "1" for row in rows),
            "fin_count": sum(_first(row["tcp.flags.fin"]) == "1" for row in rows),
            "rst_count": sum(_first(row["tcp.flags.reset"]) == "1" for row in rows),
        }
        flows.append(flow)
        for row in rows:
            if row["dns.qry.name"]:
                item = _dns_name_features(row["dns.qry.name"])
                item.update({"flow_id": flow_id, "record_type": row["dns.qry.type"],
                             "nxdomain": row["dns.flags.rcode"] == "3", "answer_count": int(row["dns.count.answers"] or 0)})
                dns_by_flow[flow_id].append(item)
            if row["tls.handshake.type"] or row["tls.handshake.ja3"] or row["tls.record.length"]:
                encrypted_by_flow[flow_id].append({
                    "flow_id": flow_id, "transport": "TLS" if protocol == "TCP" else "QUIC",
                    "ja3": row["tls.handshake.ja3"] or None, "ja3s": row["tls.handshake.ja3s"] or None,
                    "sni": row["tls.handshake.extensions_server_name"] or None,
                    "alpn": row["tls.handshake.extensions_alpn_str"] or None,
                    "early_packet_sizes": [int(row["tls.record.length"])] if row["tls.record.length"] else [],
                })
    return flows, dns_by_flow, encrypted_by_flow
