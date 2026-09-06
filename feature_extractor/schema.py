"""Canonical JSON feature record and deterministic CSV flattening."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import SCHEMA_VERSION


TOP_LEVEL_SECTIONS = (
    "entity", "volume", "tcp_behavior", "behavioral", "dns",
    "encrypted_session", "reconnaissance", "exfiltration", "availability", "provenance",
)


def flatten_record(value: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested mappings for a stable, spreadsheet-friendly CSV row."""
    result: dict[str, Any] = {}
    for key, item in value.items():
        name = f"{prefix}_{key}" if prefix else key
        if isinstance(item, Mapping):
            result.update(flatten_record(item, name))
        elif isinstance(item, list):
            result[name] = "|".join(str(part) for part in item) if item else ""
        else:
            result[name] = item
    return result


def validate_record(record: Mapping[str, Any]) -> None:
    required = {"schema_version", "run_id", "flow_id", "window_start", "window_end", *TOP_LEVEL_SECTIONS}
    missing = sorted(field for field in required if field not in record)
    if missing:
        raise ValueError(f"feature record missing fields: {', '.join(missing)}")
    if record["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version: {record['schema_version']}")


def csv_headers(records: list[Mapping[str, Any]]) -> list[str]:
    """Return deterministic headers, preserving contract order then new fields."""
    flattened = [flatten_record(record) for record in records]
    preferred = ["schema_version", "run_id", "flow_id", "window_start", "window_end"]
    headers = list(preferred)
    for row in flattened:
        for key in row:
            if key not in headers:
                headers.append(key)
    return headers
