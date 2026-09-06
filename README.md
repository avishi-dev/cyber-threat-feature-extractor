# Cyber-threat passive feature extractor

Standalone extractor for the one-way SIH traffic lab. It consumes normalized
directional flow records and optional passive DNS/TLS metadata, then emits the
same feature record as JSONL and a flattened CSV for inspection or classical
ML pipelines. It never sends traffic and never decrypts payloads.

## Input contract

The primary input is `flows.jsonl` (one normalized flow object per line). CSV
flows are also accepted. The flow fields follow
`DATASET-FORMAT-AND-FEATURES.md` from the parent project. A PCAP can be used
directly when `tshark` is installed; only headers and visible DNS/TLS metadata
are read.
Optional metadata files are JSONL records keyed by `flow_id`:

```sh
python3 -m feature_extractor.cli \
  --flows /data/raw/S0-.../flows/flows.jsonl \
  --dns-metadata /data/raw/S0-.../metadata/dns.jsonl \
  --encrypted-metadata /data/raw/S0-.../metadata/encrypted_sessions.jsonl \
  --output-jsonl /data/features/S0-features.jsonl \
  --output-csv /data/features/S0-features.csv
```

Missing metadata remains `null` and is reflected in the completeness fields.
CSV columns are flattened with names such as
`volume_packets`, `dns_name_entropy_mean`, and
`encrypted_session_ja4`.

Optional Parquet output is enabled with `--output-parquet` when `pyarrow` is
installed. The extractor never sends traffic or decrypts TLS/QUIC payloads.
Pass `--window-seconds 5` to aggregate directional flows by source into fixed
UTC five-second windows; omit it to retain one feature row per flow.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
