"""JSONL/CSV input and output helpers."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from .schema import csv_headers, flatten_record, validate_record


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            yield value


def write_jsonl(records: Iterable[Mapping[str, Any]], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            validate_record(record)
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            count += 1
    return count


def write_csv(records: list[Mapping[str, Any]], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = csv_headers(records)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = flatten_record(record)
            writer.writerow({key: "" if row.get(key) is None else row.get(key, "") for key in headers})
    return len(records)
