import csv
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))

from feature_extractor.derive import extract_record
from feature_extractor.io import write_csv, write_jsonl
from feature_extractor.schema import flatten_record


def flow():
    return {
        "run_id": "S0-20260906-001", "flow_id": "flow-1",
        "start_time": "2026-09-06T12:00:00Z", "end_time": "2026-09-06T12:00:01Z",
        "src_ip": "10.10.1.11", "dst_ip": "10.10.1.12", "src_port": 50000,
        "dst_port": 443, "protocol": "TCP", "packets": 4, "bytes": 400,
        "duration_ms": 1000, "mean_packet_size": 100, "min_packet_size": 60,
        "max_packet_size": 140, "syn_count": 1, "syn_ack_count": 1,
    }


class ExtractorTests(unittest.TestCase):
    def test_record_uses_flow_values_and_metadata(self):
        record = extract_record(flow(), dns=[{"flow_id": "flow-1", "query_length": 30, "name_entropy": 3.2, "record_type": "A"}],
                                encrypted=[{"flow_id": "flow-1", "transport": "TLS", "ja4": "abc", "early_packet_sizes": [60, 100]}])
        self.assertEqual(record["volume"]["packets"], 4)
        self.assertEqual(record["dns"]["query_length_max"], 30)
        self.assertEqual(record["encrypted_session"]["ja4"], "abc")
        self.assertGreater(record["availability"]["feature_completeness"], 0.9)

    def test_jsonl_and_csv_preserve_nulls_and_flatten_sections(self):
        record = extract_record(flow())
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path, csv_path = root / "features.jsonl", root / "features.csv"
            self.assertEqual(write_jsonl([record], json_path), 1)
            self.assertEqual(write_csv([record], csv_path), 1)
            self.assertEqual(json.loads(json_path.read_text())["flow_id"], "flow-1")
            with csv_path.open(newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["volume_packets"], "4")
            self.assertEqual(row["dns_query_length_mean"], "")
            self.assertIn("entity_src_ip", flatten_record(record))


if __name__ == "__main__":
    unittest.main()
