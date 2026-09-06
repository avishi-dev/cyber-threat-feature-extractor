"""Command-line entry point for JSONL and CSV feature extraction."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from .derive import extract_record
from .io import read_csv, read_jsonl, write_csv, write_jsonl, write_parquet
from .pcap_input import extract_pcap
from .windows import aggregate_flows


def _index_metadata(path: Path | None) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = defaultdict(list)
    if path is None:
        return result
    for record in read_jsonl(path):
        flow_id = record.get("flow_id")
        if flow_id:
            result[str(flow_id)].append(record)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Extract passive cyber-threat features without sending traffic")
    parser.add_argument("--flows", type=Path)
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--dns-metadata", type=Path)
    parser.add_argument("--encrypted-metadata", type=Path)
    parser.add_argument("--output-jsonl", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-parquet", type=Path)
    parser.add_argument("--window-seconds", type=int, default=0,
                        help="aggregate flows by source into fixed UTC windows; 0 keeps per-flow records")
    args = parser.parse_args(argv)
    if bool(args.flows) == bool(args.pcap):
        parser.error("provide exactly one of --flows or --pcap")
    dns = _index_metadata(args.dns_metadata)
    encrypted = _index_metadata(args.encrypted_metadata)
    if args.pcap:
        if not args.run_id:
            parser.error("--run-id is required with --pcap")
        flows, pcap_dns, pcap_encrypted = extract_pcap(args.pcap, args.run_id)
        for key, values in pcap_dns.items():
            dns[key].extend(values)
        for key, values in pcap_encrypted.items():
            encrypted[key].extend(values)
        source_file = str(args.pcap)
    else:
        source_file = str(args.flows)
        reader = read_csv(args.flows) if args.flows.suffix.lower() == ".csv" else read_jsonl(args.flows)
        flows = list(reader)
    if args.window_seconds:
        flows = aggregate_flows(flows, args.window_seconds)
    records = [extract_record(flow, dns=dns.get(str(flow.get("flow_id")), []),
                              encrypted=encrypted.get(str(flow.get("flow_id")), []), source_file=source_file) for flow in flows]
    write_jsonl(records, args.output_jsonl)
    write_csv(records, args.output_csv)
    if args.output_parquet:
        if not write_parquet(records, args.output_parquet):
            parser.error("--output-parquet requires pyarrow")
    print(f"extracted {len(records)} feature records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
