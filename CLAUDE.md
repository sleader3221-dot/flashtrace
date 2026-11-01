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

Verified so far (PR 1) against esptool v5.1.0 / v4.8.1 and ESP-IDF v5.3.1 source:
layout, partition table, app image, otadata. Corrections are marked
**[corrected]**. NVS / SPIFFS / LittleFS notes are still unverified.

**Layout / chip detection**
- Second-stage bootloader at 0x1000 on ESP32 and ESP32-S2; at 0x0 on ESP32-S3,
  C2, C3, C6, H2; 0x2000 on ESP32-P4 / C5. Detect by scanning those offsets for
  image magic 0xE9 and reading `chip_id` from the extended header.
  `esp_chip_id_t`: 0 ESP32, 2 S2, 5 C3, 9 S3, 12 C2, 13 C6, 16 H2, 18 P4,
  17 C5 (beta3) / 23 C5 (MP).
- Partition table default offset 0x8000 (configurable; if not found, scan
  4 KB-aligned offsets for the table magic).

**Partition table**: 32-byte entries; magic `0xAA 0x50` (LE u16 0x50AA);
type u8, subtype u8, offset u32 LE, size u32 LE, label 16 bytes (NUL-padded),
flags u32 (bit0 = encrypted, bit1 = readonly **[corrected]**). Optional MD5
entry **[corrected]**: `0xEB 0xEB` + 14 × `0xFF` (16 bytes), then the 16-byte
MD5 of all preceding entry bytes. Table ends at an all-0xFF entry; max table
length 0xC00 bytes (gen_esp32part.py pads to that with 0xFF). Types: 0 app,
1 data. App subtypes: 0x00 factory, 0x10–0x1F ota_0..ota_15, 0x20 test.
Data subtypes: 0x00 ota, 0x01 phy, 0x02 nvs, 0x03 coredump, 0x04 nvs_keys,
0x05 efuse, 0x06 undefined **[corrected]**, 0x80 esphttpd, 0x81 fat, 0x82 spiffs, 0x83 littlefs.
Validate the MD5 when present; mismatch = finding.

**App image**: 8-byte header (magic 0xE9, segment_count, spi_mode, spi_speed/size,
entry_addr u32; spi_speed = low nibble, spi_size = high nibble) + 16-byte
extended header `<BBBBHBHH4sB`: wp_pin, spi_pin_drv[3], chip_id u16,
min_chip_rev u8, min_chip_rev_full u16, max_chip_rev_full u16, reserved[4],
`hash_appended` u8. Then segments: load_addr u32, data_len u32, data.
After segments **[clarified]**: zero padding so the 1-byte XOR checksum (seed 0xEF,
over segment *data* only) is the LAST byte of a 16-byte block (relative to image
start). If hash_appended == 1, a 32-byte SHA-256 of image[0 : checksum+1] follows.
`esp_app_desc_t` (256 bytes) starts the data of the DROM segment **[clarified]**
(esptool picks the first segment in the chip's DROM address range; in IDF images
that is segment 0): magic_word u32 = 0xABCD5432, secure_version u32,
reserv1[2] u32, version[32], project_name[32], time[16], date[16], idf_ver[32],
app_elf_sha256[32], min_efuse_blk_rev_full u16, max_efuse_blk_rev_full u16,
mmu_page_size u8 (log2), reserv3[3], reserv2[18] u32.
Cross-check parsed fields against `esptool image-info` (v5) / `image_info --version 2`
(v4; v4 has no `image-info` spelling).
Secure Boot V2 signature sector: at the next 4 KB boundary after the image
(0xFF padding before it), up to 3 blocks of 1216 bytes, each beginning with magic
0xE7 then version 0x02 (RSA-PSS) **or 0x03 (ECDSA) [corrected]** (espsecure).
Report presence; do not attempt verification beyond structural checks unless a
public key is supplied.

**otadata**: partition of 2 × 4 KB sectors, each beginning with
`esp_ota_select_entry_t { u32 ota_seq; u8 seq_label[20]; u32 ota_state; u32 crc; }`
where crc = `esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4)` ==
`binascii.crc32(ota_seq_le, 0xFFFFFFFF)` (ESP-IDF otatool.py). Valid entry
**[corrected]** = crc matches AND seq != 0xFFFFFFFF AND ota_state is not
INVALID (3) / ABORTED (4) (`bootloader_common_ota_select_valid`). Active OTA slot =
(max valid ota_seq − 1) % number_of_ota_app_partitions. ota_state: 0 NEW,
1 PENDING_VERIFY, 2 VALID, 3 INVALID, 4 ABORTED, 0xFFFFFFFF UNDEFINED.

**NVS** (verified against ESP-IDF v5.3.1 `nvs_page.hpp`/`nvs_types.cpp` and
esp-idf-nvs-partition-gen 0.2.0): 4096-byte pages. Page header 32 bytes: state u32,
seq u32, version u8 (**[clarified]** 0xFE = v2 multipage blobs, 0xFF = v1),
reserved[19] = 0xFF, crc32 u32 **over bytes 4..28 [clarified]**. Page states:
0xFFFFFFFF UNINITIALIZED/EMPTY, 0xFFFFFFFE ACTIVE, 0xFFFFFFFC FULL, 0xFFFFFFF8
FREEING, 0xFFFFFFF0 CORRUPT, **0x00000000 INVALID [corrected: was missing]**.
Then a 32-byte entry-state bitmap (2 bits per entry, entry n at bits 2n..2n+1:
0b11 empty, 0b10 written, 0b00 erased, **0b01 illegal [added]**) and 126 entries
× 32 bytes: ns_index u8, type u8, span u8, chunk_index u8, crc32 u32, key[16],
data[8]. **Entry CRC [added]** = `crc32(entry[0:4] + entry[8:32], 0xFFFFFFFF)`
(`esp_rom_crc32_le(0xffffffff,…)` == `zlib.crc32(…, 0xFFFFFFFF)`).
Types: 0x01 U8, 0x11 I8, 0x02 U16, 0x12 I16, 0x04 U32, 0x14 I32, 0x08 U64,
0x18 I64, 0x21 STR, 0x41 BLOB (legacy/v1), 0x42 BLOB_DATA, 0x48 BLOB_IDX.
**Variable-length data [added]**: STR/BLOB/BLOB_DATA `data` = size u16, 2 reserved
bytes (0xFF), crc32 u32 of the payload; payload in the following span-1 slots
(STR payload includes the trailing NUL). **BLOB_IDX [added]**: `data` = total size
u32, chunk_count u8, chunk_start u8 (0x00 or 0x80, `VerOffset`); chunks are
BLOB_DATA with chunk_index chunk_start..chunk_start+count-1. Since v2 the
partition generator writes ALL `hex2bin`/`base64`/`binary` values as
BLOB_DATA+BLOB_IDX, even 4-byte ones; legacy 0x41 only appears in v1 images.
Namespace names live in ns_index 0 entries (type U8, value = index).
FORENSIC REQUIREMENT: parse ERASED entries too and report them separately as
"deleted but recoverable" — this is a key differentiator. An erased entry is only
trusted when its header CRC is valid (erasure flips only bitmap bits).
**Wi-Fi [verified, partially]**: namespace `nvs.net80211`; key names confirmed
from strings in the Wi-Fi driver binary (`esp32-wifi-lib/esp32/libnet80211.a`):
`sta.ssid`, `sta.pswd`, `ap.ssid`, `ap.passwd`, `sta.pmk`, `ap.pmk_info`,
`sta.apinfo`, `sta.authmode`, … esp-idf-nvs-partition-gen 0.2.0 special-cases
`sta.ssid`/`sta.pswd` (it auto-adds `sta.apinfo`, `sta.pmk`, `sta.apsw`) and adds
the `blob_sz_fill(N;0xPP)` (u32 length + bytes + padding) and `blob_fill` encodings
for them. UNVERIFIED: the exact blob layout written by the closed-source driver.
FlashTrace decodes defensively: u32 length prefix when plausible (1..32 SSID,
1..64 passphrase, zero padding after), else NUL-terminated; STR values accepted too.
Encrypted NVS: page headers/bitmaps stay plaintext, entries are XTS-encrypted, so
FlashTrace reports "NVS encrypted" when an nvs_keys partition exists and no
written entry has a valid CRC, or when no page header is valid and entropy > 7.5.

**SPIFFS [added]** (from ESP-IDF v5.3.1 `components/spiffs/spiffsgen.py`; FlashTrace's
`tools/corpus/spiffs_writer.py` is checked byte-identical to it in CI): ESP-IDF
defaults page 256, block 4096, obj_name_len 32, meta_len 4, little-endian, magic +
magic_len on. Per block: one object-lookup page of u16 obj ids (MSB set = index page,
0xFFFF free), magic at lookup slot 126 = `(0x20140529 ^ 256 ^ (blocks - bix)) & 0x1FFFF`.
Data page: obj_id u16, span_ix u16, flags u8 (0xFC), 251 content bytes. Index page:
obj_id|0x8000, span_ix, flags 0xF8, 3 pad bytes, then (span 0 only) size u32, type
u8 (1 = file), name[32], meta[4], then u16 page indices (103 per head page, 124 per
follow-up index page). ASSUMPTION (spiffsgen only writes fresh images): pages with
flag bit 7 cleared or lookup id 0x0000 are deleted.

**LittleFS [added]**: parsed only through littlefs-python 0.19.0. `LittleFS(mount=True)`
**formats** the buffer on mount failure, so always `mount=False` + explicit `mount()`
on a copy. On-flash file offsets are not exposed by the API; FlashTrace locates file
content by searching the partition and marks files it cannot locate.

**Coredump [added]** (ESP-IDF v5.3.1 `esp_core_dump_types.h`): `core_dump_header_t
{data_len, version, tasks_num, tcb_sz, mem_segs_num, chip_rev}` (u32 each);
`version = chip_id<<16 | major<<8 | minor`, major 0 binary / 1 ELF. Erased = all 0xFF.
ELF dumps contain an ELF32 ET_CORE file; FlashTrace looks for `\x7fELF` in the first
64 bytes (exact ELF-variant prefix layout not verified against a real device dump).

**Secure Boot V2 [clarified]**: CLAUDE.md rule text says version 0x02; espsecure also
emits 0x03 (ECDSA). SEC.NO_SECURE_BOOT accepts either.

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
**[clarified]** Implementation: each device's `ground_truth.json` lists `must_fire`,
`must_not_fire` (every other registered rule unless `dont_care`) and `dont_care`.
A forbidden rule firing on any device fails CI. Because every plaintext dump lacks
flash encryption, clean_control's only `must_fire` is the posture finding
SEC.NO_FLASH_ENCRYPTION, and the gate fails on any *unexpected* finding >= medium
there (open question, see PROGRESS.md "Blocked / needs human").
