# JSON report schema (version 1.0)

`flashtrace analyze --format json` writes `report.json`; `flashtrace diff` writes
`diff.json`. Both are UTF-8 JSON objects with a `schema_version` and a `kind`.
Offsets are absolute byte offsets into the dump; `*_hex` fields repeat them in hex.
All SHA-256 values are lowercase hex.

## Analysis report (`kind: "analysis"`)

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | `"1.0"` |
| `kind` | string | `"analysis"` |
| `tool` | object | `{name, version}` |
| `dump` | object | `sha256`, `size`, `chip` (requested or detected), `chip_detected`, `chip_id`, `bootloader_offset`, `analysed_at` (ISO-8601 UTC), `secrets_revealed` |
| `encryption` | object | `likely` (bool), `reason` (string or null) |
| `partition_table` | object or null | `offset`, `md5_present`, `md5_valid` (null if no MD5 entry), `end_marker_found` |
| `partitions[]` | array | `label`, `type`, `subtype`, `offset`, `offset_hex`, `size`, `present_bytes`, `entropy` (bits/byte), `sha256`, `encrypted_flag`, `readonly_flag` |
| `apps[]` | array | `partition`, `offset`, `image_length`, `chip`, `segments`, `checksum_valid`, `sha256_valid`, `image_sha256` (over `[offset, offset+image_length)`), `signature_blocks[] {offset, version, scheme}`, `app_desc {project_name, version, secure_version, idf_ver, date, time, app_elf_sha256}` or null |
| `otadata` | object or null | `offset`, `active_slot` (label or null), `entries[] {index, offset, seq, state, crc_ok, valid, erased}` |
| `nvs[]` | array | `partition`, `encrypted`, `encryption_reason`, `pages`, `namespaces {index: name}`, `entries[]`, `recovered_deleted[]` (see NVS entry) |
| `filesystems[]` | array | `partition`, `type` (`spiffs`/`littlefs`), `mounted`, `detail`, `directories[]`, `files[] {path, size, sha256, located, complete, offset}` |
| `coredump` | object or null | `partition`, `format` (`empty`/`binary`/`elf`/`unknown`), `size`, `data_len`, `tasks` |
| `summary` | object | `finding_count`, `severity_counts {info, low, medium, high, critical}`, `max_severity`, `rules_fired[]` |
| `findings[]` | array | see Finding |
| `timeline[]` | array | `ts_source` (where the value came from), `value` (raw), `iso` (normalised UTC or null), `trust` (always `"device-reported, untrusted"`), `evidence` |
| `rule_errors[]` | array of string | rules that raised; non-empty ⇒ exit code 2 |

### Finding

| Field | Type | Description |
|---|---|---|
| `id` | string | stable: `<rule_id>:<16 hex>` derived from the rule and its evidence |
| `rule_id` | string | e.g. `NVS.WIFI_CREDENTIALS` (see docs/rules.md) |
| `severity` | string | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `title` | string | human-readable |
| `detail` | object | rule-specific; secret values appear masked (`ab****yz`) with `redacted: true` and the SHA-256 of the unredacted value (`value_sha256` / `password_sha256`) |
| `evidence[]` | array | see Evidence |
| `attck` | array of string | ATT&CK for ICS technique IDs (only confirmed mappings) |
| `confidence` | number | 0–1; halved when flash encryption is likely |

### Evidence

| Field | Type | Description |
|---|---|---|
| `partition` | string or null | partition label, null for table/otadata-level structures |
| `offset` / `offset_hex` | int / string | absolute dump offset |
| `length` | int | bytes |
| `sha256` | string | SHA-256 of `dump[offset:offset+length]` |
| `preview_hex` | string or null | first ≤ 64 bytes as hex; null when the evidence backs a redacted secret |
| `preview_redacted` | bool | whether the preview was withheld |

### NVS entry

`namespace`, `key`, `type` (`U8`…`I64`, `STR`, `BLOB`, `BLOB_IDX`, `BLOB_DATA`),
`status` (`written`/`erased`), `value` (int, string, hex-preview for blobs, or masked),
`value_redacted`, `value_sha256`, `offset`, `offset_hex`, `page`, `slot`,
`header_crc_ok`, `data_crc_ok`, `complete` (reassembled blob had every chunk).

## Diff report (`kind: "diff"`)

| Field | Type | Description |
|---|---|---|
| `schema_version`, `kind` | string | `"1.0"`, `"diff"` |
| `dump_a`, `dump_b` | object | `{sha256, size}` |
| `summary` | object | `finding_count`, `rules_fired[]` |
| `findings[]` | array | Findings with `DIFF.*` rule IDs; `detail.evidence_dumps[i]` is `"A"` or `"B"` for `evidence[i]` |

## Benchmark results (`bench_results.json`)

`overall {tp, fp, fn, precision, recall, f1}`, `gate {recall_threshold, passed,
violations[]}`, `per_rule {rule_id: {tp, fp, fn, precision, recall, f1}}`,
`devices[] {device, must_fire, fired, missed, forbidden_fired, finding_count,
rule_errors}`. Precision/recall/F1 are null when undefined (no positives).
