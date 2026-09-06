"""Derive passive feature records from normalized flows and optional metadata."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping
from typing import Any

from . import SCHEMA_VERSION


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _stddev(values: list[float]) -> float | None:
    if not values:
        return None
    average = sum(values) / len(values)
    return math.sqrt(sum((item - average) ** 2 for item in values) / len(values))


def _interarrivals(times: list[float]) -> list[float]:
    ordered = sorted(times)
    return [(right - left) * 1000 for left, right in zip(ordered, ordered[1:])]


def _entropy(values: list[Any]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _metadata_for(flow_id: str, metadata: Mapping[str, list[Mapping[str, Any]]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in metadata.get(flow_id, []):
        merged.update(item)
    return merged


def _dns_features(items: list[Mapping[str, Any]]) -> tuple[dict[str, Any], int]:
    if not items:
        return {
            "query_count": 0, "query_length_mean": None, "query_length_max": None,
            "label_count_mean": None, "max_label_length": None, "name_entropy_mean": None,
            "digit_ratio_mean": None, "unique_char_ratio_mean": None, "nxdomain_ratio": None,
            "txt_query_ratio": None, "encoded_length_estimate": None, "dns_tunnel_indicator": None,
        }, 11
    lengths = [_number(item.get("query_length")) for item in items]
    entropy = [_number(item.get("name_entropy")) for item in items if item.get("name_entropy") is not None]
    digit = [_number(item.get("digit_ratio")) for item in items if item.get("digit_ratio") is not None]
    unique = [_number(item.get("unique_char_ratio")) for item in items if item.get("unique_char_ratio") is not None]
    labels = [_number(item.get("label_count")) for item in items if item.get("label_count") is not None]
    nxdomain = [bool(item.get("nxdomain")) for item in items if item.get("nxdomain") is not None]
    txt = [str(item.get("record_type", "")).upper() == "TXT" for item in items]
    return {
        "query_count": len(items), "query_length_mean": _mean(lengths), "query_length_max": max(lengths),
        "label_count_mean": _mean(labels), "max_label_length": max((_number(item.get("max_label_length")) for item in items), default=None),
        "name_entropy_mean": _mean(entropy), "digit_ratio_mean": _mean(digit), "unique_char_ratio_mean": _mean(unique),
        "nxdomain_ratio": sum(nxdomain) / len(nxdomain) if nxdomain else None,
        "txt_query_ratio": sum(txt) / len(txt),
        "encoded_length_estimate": sum(_number(item.get("encoded_length_estimate")) for item in items),
        "dns_tunnel_indicator": any(item.get("tunnel_indicator") is True for item in items),
    }, 0


def _encrypted_features(items: list[Mapping[str, Any]]) -> tuple[dict[str, Any], int]:
    if not items:
        return {"transport": None, "tls_version": None, "ja3": None, "ja3s": None, "ja4": None,
                "sni_visible": False, "alpn": None, "early_packet_size_mean": None,
                "early_packet_size_stddev": None, "early_interarrival_mean_ms": None,
                "metadata_completeness": 0.0}, 12
    item = items[-1]
    sizes = [_number(x) for x in item.get("early_packet_sizes", [])]
    interarrival = [_number(x) for x in item.get("early_interarrival_ms", [])]
    return {"transport": item.get("transport"), "tls_version": item.get("tls_version"), "ja3": item.get("ja3"),
            "ja3s": item.get("ja3s"), "ja4": item.get("ja4"), "sni_visible": bool(item.get("sni")),
            "alpn": item.get("alpn"), "early_packet_size_mean": _mean(sizes),
            "early_packet_size_stddev": _stddev(sizes), "early_interarrival_mean_ms": _mean(interarrival),
            "metadata_completeness": _number(item.get("metadata_completeness"))}, 0


def extract_record(flow: Mapping[str, Any], *, dns: list[Mapping[str, Any]] | None = None,
                   encrypted: list[Mapping[str, Any]] | None = None,
                   source_file: str | None = None, extractor_version: str = "0.1.0") -> dict[str, Any]:
    """Create one schema-versioned record; absent evidence stays null."""
    packets = int(_number(flow.get("packets")))
    byte_count = int(_number(flow.get("bytes")))
    duration_ms = int(_number(flow.get("duration_ms")))
    duration_seconds = max(duration_ms / 1000, 1e-6)
    src_port, dst_port = flow.get("src_port"), flow.get("dst_port")
    packet_sizes = [_number(x) for x in flow.get("packet_sizes", [])]
    interarrivals = [_number(x) for x in flow.get("interarrivals_ms", [])] or _interarrivals([_number(x) for x in flow.get("packet_times", [])])
    source_ports_seen = list(flow.get("source_ports_seen", [])) or ([src_port] if src_port is not None else [])
    destination_ports_seen = list(flow.get("destination_ports_seen", [])) or ([dst_port] if dst_port is not None else [])
    destination_hosts_seen = list(flow.get("destination_hosts_seen", [])) or ([flow.get("dst_ip")] if flow.get("dst_ip") else [])
    dns_section, dns_missing = _dns_features(dns or [])
    encrypted_section, encrypted_missing = _encrypted_features(encrypted or [])
    protocol = str(flow.get("protocol") or "unknown").upper()
    flow_id = str(flow.get("flow_id", ""))
    record = {
        "schema_version": SCHEMA_VERSION,
        "run_id": flow.get("run_id"), "flow_id": flow_id,
        "window_start": flow.get("start_time") or flow.get("start_time_utc"),
        "window_end": flow.get("end_time") or flow.get("end_time_utc"),
        "entity": {"src_ip": flow.get("src_ip"), "dst_ip": flow.get("dst_ip"), "src_port": src_port,
                   "dst_port": dst_port, "protocol": protocol, "src_role": flow.get("src_role"),
                   "dst_role": flow.get("dst_role"), "src_is_internal": flow.get("src_is_internal"),
                   "dst_is_internal": flow.get("dst_is_internal")},
        "volume": {"packets": packets, "bytes": byte_count, "duration_ms": duration_ms,
                   "packets_per_second": packets / duration_seconds, "bytes_per_second": byte_count / duration_seconds,
                   "mean_packet_size": _mean(packet_sizes) if packet_sizes else (_number(flow.get("mean_packet_size")) or None),
                   "min_packet_size": min(packet_sizes) if packet_sizes else flow.get("min_packet_size"),
                   "max_packet_size": max(packet_sizes) if packet_sizes else flow.get("max_packet_size"),
                   "packet_size_stddev": _stddev(packet_sizes) if packet_sizes else flow.get("packet_size_stddev")},
        "tcp_behavior": {"syn_count": flow.get("syn_count", 0), "syn_ack_count": flow.get("syn_ack_count", 0),
                         "ack_count": flow.get("ack_count", 0), "rst_count": flow.get("rst_count", 0),
                         "fin_count": flow.get("fin_count", 0),
                         "tcp_syn_ratio": (flow.get("syn_count", 0) / packets) if packets else None,
                         "handshake_observed": bool(flow.get("tcp_handshake_observed", False)),
                         "established_evidence": bool(flow.get("tcp_established_evidence", False))},
        "behavioral": {"unique_destination_ports": flow.get("unique_destination_ports", len(set(destination_ports_seen))),
                       "unique_destination_hosts": flow.get("unique_destination_hosts", len(set(destination_hosts_seen))),
                       "source_port_entropy": flow.get("source_port_entropy", _entropy(source_ports_seen)),
                       "destination_port_entropy": flow.get("destination_port_entropy", _entropy(destination_ports_seen)),
                       "source_ip_entropy": flow.get("source_ip_entropy", 0.0),
                       "destination_ip_entropy": flow.get("destination_ip_entropy", 0.0),
                       "interarrival_mean_ms": flow.get("interarrival_mean_ms", _mean(interarrivals)),
                       "interarrival_stddev_ms": flow.get("interarrival_stddev_ms", _stddev(interarrivals)),
                       "periodicity_score": flow.get("periodicity_score"),
                       "one_way_flow": flow.get("one_way_flow", True),
                       "outbound_inbound_ratio": flow.get("outbound_inbound_ratio")},
        "dns": dns_section,
        "encrypted_session": encrypted_section,
        "reconnaissance": {"host_fanout": flow.get("host_fanout", 1), "port_fanout": flow.get("port_fanout", 1),
                            "connection_attempts": flow.get("connection_attempts", packets),
                            "failed_connection_ratio": flow.get("failed_connection_ratio"),
                            "scan_pattern_score": flow.get("scan_pattern_score")},
        "exfiltration": {"upstream_bytes": flow.get("upstream_bytes"), "downstream_bytes": flow.get("downstream_bytes"),
                         "outbound_inbound_ratio": flow.get("outbound_inbound_ratio"),
                         "burstiness": flow.get("burstiness"), "large_transfer_indicator": flow.get("large_transfer_indicator")},
        "availability": {"packet_features_available": True, "dns_features_available": bool(dns),
                          "tls_features_available": bool(encrypted), "flow_features_available": True,
                          "missing_feature_count": dns_missing + encrypted_missing,
                          "feature_completeness": round(1 - ((dns_missing + encrypted_missing) / 23), 6)},
        "provenance": {"source_file": source_file, "extractor_version": extractor_version,
                       "input_type": "flow_and_passive_metadata", "label": flow.get("label"),
                       "label_source": flow.get("label_source")},
    }
    return record
