"""Bounded time-window aggregation for streaming-compatible passive features."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def aggregate_flows(flows: list[dict[str, Any]], window_seconds: int) -> list[dict[str, Any]]:
    """Aggregate directional flows by source and fixed UTC window.

    The resulting synthetic flow retains packet/byte evidence and the original
    flow IDs for provenance. Metadata joins are intentionally performed before
    this stage by the caller when metadata-level window features are needed.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    groups: dict[tuple[str, str, datetime], list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        start = _parse(str(flow.get("start_time") or flow.get("start_time_utc")))
        epoch = int(start.timestamp())
        bucket = datetime.fromtimestamp(epoch - (epoch % window_seconds), timezone.utc)
        groups[(str(flow.get("run_id", "")), str(flow.get("src_ip", "")), bucket)].append(flow)
    result: list[dict[str, Any]] = []
    for (run_id, source, bucket), items in sorted(groups.items(), key=lambda entry: entry[0][2]):
        ends = [_parse(str(item.get("end_time") or item.get("end_time_utc"))) for item in items]
        destinations = {str(item.get("dst_ip")) for item in items if item.get("dst_ip")}
        destination_ports = {item.get("dst_port") for item in items if item.get("dst_port") is not None}
        packets = sum(int(item.get("packets") or 0) for item in items)
        byte_count = sum(int(item.get("bytes") or 0) for item in items)
        duration_ms = max(1, int((max(ends) - bucket).total_seconds() * 1000))
        sizes = [size for item in items for size in item.get("packet_sizes", [])]
        result.append({
            "run_id": run_id, "flow_id": f"window-{run_id}-{source}-{bucket.strftime('%Y%m%d%H%M%S')}",
            "start_time": _iso(bucket), "end_time": _iso(bucket + timedelta(seconds=window_seconds)),
            "src_ip": source, "dst_ip": next(iter(destinations), None), "src_port": None,
            "dst_port": next(iter(destination_ports), None), "protocol": "MIXED" if len({item.get("protocol") for item in items}) > 1 else items[0].get("protocol"),
            "src_is_internal": items[0].get("src_is_internal"), "dst_is_internal": all(item.get("dst_is_internal") for item in items),
            "packets": packets, "bytes": byte_count, "duration_ms": duration_ms, "packet_sizes": sizes,
            "packet_times": [time for item in items for time in item.get("packet_times", [])],
            "syn_count": sum(int(item.get("syn_count") or 0) for item in items),
            "syn_ack_count": sum(int(item.get("syn_ack_count") or 0) for item in items),
            "ack_count": sum(int(item.get("ack_count") or 0) for item in items),
            "fin_count": sum(int(item.get("fin_count") or 0) for item in items),
            "rst_count": sum(int(item.get("rst_count") or 0) for item in items),
            "unique_destination_ports": len(destination_ports), "unique_destination_hosts": len(destinations),
            "destination_ports_seen": list(destination_ports), "destination_hosts_seen": list(destinations),
            "one_way_flow": True, "source_flow_ids": [str(item.get("flow_id")) for item in items],
            "upstream_bytes": byte_count, "downstream_bytes": 0,
            "outbound_inbound_ratio": None if byte_count == 0 else None,
        })
    return result
