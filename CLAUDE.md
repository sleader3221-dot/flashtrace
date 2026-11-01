# FlashTrace — Forensic Triage for ESP32 Flash Dumps

## Mission
FlashTrace ingests a raw ESP32-family SPI flash dump (`.bin`, typically 2/4/8/16 MB)
and produces an evidence-linked forensic report: what is on the device, what
secrets are exposed, what changed, and whether firmware shows signs of tampering.
Every finding MUST cite its byte offset, length, partition, and SHA-256 of the
supporting bytes. No finding without evidence.

Intended use: analysing devices you own or are authorised to examine
(incident response, security research, CTF). Secrets are REDACTED in output by
default; `--reveal-secrets` must be passed explicitly.

## Engineering rules (non-negotiable)
1. Python 3.11+, package layout `src/flashtrace/`, tests in `tests/`, `pyproject.toml`
   with `ruff`, `mypy --strict` on `src/`, `pytest`.
2. Parsers are pure functions over `bytes`/`memoryview`; no global state; never
   trust lengths/offsets from the dump — bounds-check everything. A malformed or
   hostile dump must never crash the tool: record an `anomaly` finding instead.
3. Deterministic core: all detection is rule-based and reproducible. Any LLM
   layer is optional and only explains existing findings — it never creates them.
4. Do NOT guess binary formats from memory. The format notes below are a
   starting point; every parser must be validated against bytes produced by
   official tooling (esptool, esp-idf-nvs-partition-gen, littlefs-python, etc.).
   If an installed tool's behaviour contradicts these notes, the tool wins:
   fix the notes in this file and say so in the PR.
5. Before using any third-party Python API, read its installed source
   (`python -c "import x, inspect; print(inspect.getsourcefile(x))"`) to confirm
   the real function names and signatures for the installed version. Pin versions.
6. Every module ships with tests. A task is not done until `ruff check`,
   `mypy`, and `pytest` all pass. Commit in small, logical steps.
7. Never commit generated dumps > 1 MB to git; generate them in tests/fixtures
   at test time or in CI, and cache.

## CLI (target)
```
flashtrace analyze dump.bin [--chip auto|esp32|esp32s3|esp32c3|esp32c6]
                            [--baseline known_good_app.bin ...]
                            [--out report_dir/] [--format json|html|md]
                            [--reveal-secrets]
flashtrace diff dumpA.bin dumpB.bin --out diff_dir/
flashtrace bench corpus_dir/ --out bench_results.json
```

## Architecture
```
src/flashtrace/
  io.py            # load dump, chip/bootloader-offset detection, entropy
  partition.py     # partition table
  appimage.py      # app image header/segments/checksum/SHA-256/app_desc/secure-boot sig block
  otadata.py       # OTA select entries, active slot, rollback state
  nvs.py           # NVS pages/entries incl. ERASED (deleted) entries
  fs/spiffs.py     # SPIFFS file listing/extraction (stage 2)
  fs/littlefs.py   # LittleFS via littlefs-python (stage 2)
  coredump.py      # locate + summarise coredump partition
  secrets.py       # credential/key/URL/cert/MQTT detectors over strings & NVS
  rules/           # one file per detection rule, each returning Finding objects
  evidence.py      # SQLite evidence store
  attck.py         # MITRE ATT&CK for ICS mapping table (data file, not hardcoded logic)
  report/          # json, markdown, self-contained html renderer
  cli.py
tools/corpus/      # synthetic device generator + ground truth
```

## Core data model
```python
@dataclass(frozen=True)
class Evidence:
    partition: str | None
    offset: int          # absolute offset in dump
    length: int
    sha256: str          # of dump[offset:offset+length]

@dataclass(frozen=True)
class Finding:
    id: str              # stable: rule_id + evidence hash prefix
    rule_id: str         # e.g. "NVS.WIFI_CREDENTIALS"
    severity: Literal["info","low","medium","high","critical"]
    title: str
    detail: dict         # structured, secrets redacted unless revealed
    evidence: tuple[Evidence, ...]
    attck: tuple[str, ...]   # ATT&CK for ICS technique IDs, may be empty
    confidence: float
```
SQLite tables: `dump(sha256, size, chip, analysed_at)`, `artifact(...)`,
`finding(...)`, `evidence(...)`, `timeline(ts_source, value, finding_id)`.
Timeline entries must record WHERE a timestamp came from (e.g. app_desc build
date, NVS key) — these are device-reported, not trusted wall-clock.

## Format notes (verify against official tool output — see rule 4)

**Layout / chip detection**
- Second-stage bootloader at 0x1000 on ESP32 and ESP32-S2; at 0x0 on ESP32-S3,
  C3, C6, H2; 0x2000 on ESP32-P4 / C5. Detect by scanning those offsets for
  image magic 0xE9 and reading `chip_id` from the extended header.
- Partition table default offset 0x8000 (configurable; if not found, scan
  4 KB-aligned offsets for the table magic).

**Partition table**: 32-byte entries; magic `0xAA 0x50` (LE u16 0x50AA);
type u8, subtype u8, offset u32 LE, size u32 LE, label 16 bytes (NUL-padded),
flags u32 (bit0 = encrypted). Optional MD5 entry: magic `0xEB 0xEB`, then MD5
of all preceding entry bytes. Table ends at an all-0xFF entry. Types: 0 app,
1 data. App subtypes: 0x00 factory, 0x10–0x1F ota_0..ota_15, 0x20 test.
Data subtypes: 0x00 ota, 0x01 phy, 0x02 nvs, 0x03 coredump, 0x04 nvs_keys,
0x05 efuse, 0x80 esphttpd, 0x81 fat, 0x82 spiffs, 0x83 littlefs.
Validate the MD5 when present; mismatch = finding.

**App image**: 8-byte header (magic 0xE9, segment_count, spi_mode, spi_speed/size,
entry_addr u32) + 16-byte extended header (incl. chip_id u16, min chip rev,
`hash_appended` u8 as last byte). Then segments: load_addr u32, data_len u32,
data. After segments: pad to 16-byte boundary, 1-byte XOR checksum (seed 0xEF
over segment data). If hash_appended, 32-byte SHA-256 of the image follows.
`esp_app_desc_t` sits at the start of the first segment's data (DROM):
magic_word u32 = 0xABCD5432, secure_version u32, reserv1[2] u32, version[32],
project_name[32], time[16], date[16], idf_ver[32], app_elf_sha256[32], ...
Cross-check parsed fields against `esptool image-info` (v5) / `image_info` (v4).
Secure Boot V2 signature block: appended at a 4 KB-aligned offset after the image,
begins with magic byte 0xE7 then version byte 0x02. Report presence; do not
attempt verification beyond structural checks unless a public key is supplied.

**otadata**: partition of 2 × 4 KB sectors, each beginning with
`esp_ota_select_entry_t { u32 ota_seq; u8 seq_label[20]; u32 ota_state; u32 crc; }`
where crc = CRC32 (as used by ESP-IDF — verify) over the 4-byte ota_seq. Valid
entry = crc matches and seq != 0xFFFFFFFF. Active OTA slot =
(max valid ota_seq − 1) % number_of_ota_app_partitions. ota_state: 0 NEW,
1 PENDING_VERIFY, 2 VALID, 3 INVALID, 4 ABORTED, 0xFFFFFFFF UNDEFINED.

**NVS**: 4096-byte pages. Page header 32 bytes: state u32, seq u32, version u8,
reserved, crc32 u32. Page states: 0xFFFFFFFF EMPTY, 0xFFFFFFFE ACTIVE,
0xFFFFFFFC FULL, 0xFFFFFFF8 FREEING, 0xFFFFFFF0 CORRUPT.
Then a 32-byte entry-state bitmap (2 bits per entry: 0b11 empty, 0b10 written,
0b00 erased) and 126 entries × 32 bytes:
ns_index u8, type u8, span u8, chunk_index u8, crc32 u32, key[16], data[8].
Types: 0x01 U8, 0x11 I8, 0x02 U16, 0x12 I16, 0x04 U32, 0x14 I32, 0x08 U64,
0x18 I64, 0x21 STR, 0x41 BLOB (legacy), 0x42 BLOB_DATA, 0x48 BLOB_IDX.
Namespace names live in ns_index 0 entries. Multi-span entries carry data in
following entry slots. Chunked blobs: reassemble BLOB_DATA chunks via BLOB_IDX.
FORENSIC REQUIREMENT: parse ERASED entries too and report them separately as
"deleted but recoverable" — this is a key differentiator.
Wi-Fi station config is expected under namespace `nvs.net80211`
(e.g. keys `sta.ssid`, `sta.pswd`); confirm exact key names and blob layouts
by generating NVS images with esp-idf-nvs-partition-gen and inspecting real
ESP-IDF source if available in the environment. Encrypted NVS (nvs_keys
partition present, random-looking pages) → report "NVS encrypted", do not parse.

**Encryption heuristics**: if partition-table magic absent at expected offset AND
Shannon entropy of the region > 7.5 bits/byte, report likely flash encryption.
Compute per-partition entropy and include it in the report.

## Detection rules (initial set; each = one file in rules/, each tested)
- PT.MD5_MISMATCH, PT.OVERLAP, PT.OUT_OF_BOUNDS
- IMG.CHECKSUM_BAD, IMG.SHA256_BAD, IMG.NO_APP_DESC
- IMG.UNKNOWN_BUILD (app SHA-256 not in --baseline set)
- IMG.SLOT_DIVERGENCE (ota_0 and ota_1 differ in project_name / idf_ver / unexpected version jump)
- OTA.ROLLBACK_OR_DOWNGRADE (active slot's version/secure_version < other slot's)
- OTA.PENDING_VERIFY / OTA.INVALID_ACTIVE
- NVS.WIFI_CREDENTIALS, NVS.DELETED_SECRET (erased entry that looks like a secret)
- SEC.HARDCODED_CREDENTIAL, SEC.API_KEY (AWS AKIA…, generic high-entropy tokens),
  SEC.PRIVATE_KEY (PEM), SEC.CERT (PEM/DER), SEC.MQTT_BROKER, SEC.URL
- SEC.NO_FLASH_ENCRYPTION, SEC.NO_SECURE_BOOT (structural absence of sig block)
- FS.SUSPICIOUS_FILE (scripts, keys, unexpected binaries in SPIFFS/LittleFS)
- CORE.PRESENT (coredump exists → device crashed; summarise header)

## Benchmark (proves the tool works)
`tools/corpus/` generates synthetic 4 MB ESP32 dumps with KNOWN planted
conditions and writes `ground_truth.json` per device. Required devices:
clean_control, wifi_creds_in_nvs, deleted_token_in_nvs, hardcoded_aws_key_in_app,
backdoored_ota_slot (unknown build + slot divergence), forced_rollback,
pending_verify_ota, pem_private_key_in_spiffs, corrupted_partition_md5,
encrypted_flash_simulated (random bytes over table+apps).
`flashtrace bench` computes per-rule precision/recall/F1 and overall scores.
CI fails if overall recall < 0.95 or any false positive on clean_control.
