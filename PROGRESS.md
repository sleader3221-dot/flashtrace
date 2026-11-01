# FlashTrace — progress log (phases 2–5, branch `feat/phases-2-5`)

## Baseline (step 0)

- **Session 1 was NOT merged into `main`** when this session started (`origin/main`
  still at `ab0cf1f`). The foundation lives in PR #1 (`claude/nice-fermi-3tx67n`).
  This branch is therefore based on PR #1's head; once PR #1 merges, this PR's
  diff shrinks to phases 2–5 only.
- PR #1 CI was red: 4/79 failures, all in the test's expected string
  (`esptool` prints `ESP32-C3`, not `ESP32C3`). Fixed on PR #1 as
  `fix: expect esptool CHIP_NAME spelling` (8576df8). Every field-by-field
  esptool comparison and all hypothesis fuzz tests passed in CI.
- Local baseline: ruff ✓, mypy --strict ✓, pytest 67 passed / 2 skipped.

## Environment constraint

The development container **cannot reach PyPI** (DNS + egress policy), and
installing third-party code from source was refused by the permission
classifier. Consequences and mitigation:

| Package | Local | Strategy |
|---|---|---|
| esptool 5.1.0 | ✗ | source read at tag; tests run in CI (`FLASHTRACE_REQUIRE_TOOLS=1`) |
| esp-idf-nvs-partition-gen 0.2.0 | ✗ | source read at tag; FlashTrace ships an NVS *writer* in `tests/fixtures/nvs_writer.py` that follows it line by line, and CI asserts **byte-identical** output vs the official tool |
| spiffsgen.py (ESP-IDF v5.3.1) | ✗ (not on PyPI) | same approach: `tools/corpus/spiffs_writer.py`; CI downloads spiffsgen.py at the pinned tag and asserts byte identity |
| littlefs-python 0.19.0 | ✗ (C ext) | parser + tests; tests run only in CI |
| typer 0.27.3 | ✗ | `cli.py` is a thin typer wrapper over `commands.py` (pure functions, tested locally); typer-level tests run in CI |
| hypothesis 6.139.3 | ✗ | fuzz tests run in CI; seeded stdlib robustness sweep runs everywhere |
| cryptography, PyYAML | ✓ installed | used directly |

## Plan

| Phase | Files | Order |
|---|---|---|
| A NVS + secrets | `nvs.py`, `wifi.py`, `strings.py`, `secrets.py`, `redact.py`, `rules/{__init__,registry,nvs_wifi_credentials,nvs_deleted_secret,sec_*}.py`, `tests/fixtures/nvs_writer.py`, tests | writer → parser → erasure recovery → secrets → rules |
| B FS/coredump/posture | `fs/spiffs.py`, `fs/littlefs.py`, `coredump.py`, `posture.py`, `rules/{pt_*,img_*,ota_*,fs_*,core_*,sec_no_*}.py`, `tools/corpus/spiffs_writer.py` | spiffs → littlefs → coredump → posture → rules |
| C pipeline/CLI/bench | `pipeline.py`, `context.py`, `commands.py`, `cli.py`, `diff.py`, `bench.py`, `tools/corpus/generate.py` | pipeline → CLI → corpus → bench → CI gate |
| D ATT&CK/reports/docs | `attck.py`, `data/attck_ics_map.yaml`, `report/{json,markdown,html}.py`, `docs/*.md`, `examples/`, README | map → reports → docs → examples |

## Phase A — NVS parser and secret detection ✅

**Done**
- `nvs.py`: pages (header CRC over bytes 4..28, all 6 states), entry bitmap, all 12
  entry types, multi-span STR, legacy BLOB, BLOB_DATA reassembly via BLOB_IDX
  (chunk_start aware), per-entry header + payload CRC (mismatch → anomaly),
  namespaces, **ERASED-entry recovery** (`recovered_deleted`, incl. erased chunked
  blobs and orphan chunks), encrypted-NVS detection (no parse), Evidence for every
  value (header+span bytes, plus payload-only evidence with exact SHA-256).
- `tools/corpus/nvs_writer.py`: port of esp-idf-nvs-partition-gen 0.2.0. **CI proves it
  byte-identical** to the official tool (`tests/test_nvs_official.py`, 3 cases incl. a
  300-entry multi-page image).
- `wifi.py`: `nvs.net80211` decoding (key names confirmed from `libnet80211.a`).
- `strings.py` (ASCII + UTF-16LE, offsets kept), `secrets.py` (PEM keys, PEM/DER certs
  via `cryptography`, AWS key IDs, entropy-gated generic tokens, MQTT, URLs,
  credential assignments, URL userinfo), `redact.py` (first/last 2 chars).
- Rule registry (`rules/__init__.py`, auto-discovery) + `context.py` (parsed dump +
  scan regions that map file/NVS bytes back to dump offsets).
- Rules: NVS.WIFI_CREDENTIALS, NVS.DELETED_SECRET, SEC.HARDCODED_CREDENTIAL,
  SEC.API_KEY, SEC.PRIVATE_KEY, SEC.CERT, SEC.MQTT_BROKER, SEC.URL — each with
  positive + negative tests; clean fixture yields zero SEC.*/NVS.* findings.

**Tests**: CI 133 passed / 0 skipped (3.11 + 3.12); local 116 passed / 3 skipped
(tool-dependent modules).

**Bugs found by the new tests and fixed**: generic-token regex could not match after
`=`; DER detection missed certs whose tbsCertificate uses the 1-byte length form
(`30 81`); credential regex missed `admin_password=` style keys.

**CLAUDE.md corrections**: NVS header CRC range, INVALID page state, ILLEGAL bitmap
state, entry/payload CRC definitions, varlen and BLOB_IDX layouts, v2 writes all
binary values as chunked blobs; Wi-Fi key names verified, blob layout still unverified.

**Known gaps**: v1 (0xFF) NVS images only tested via a hand-built legacy BLOB page;
NVS encryption detection is heuristic (no XTS decryption by design).

## Phase B — filesystems, coredump, OTA logic, crypto posture ✅

**Done**
- `fs/spiffs.py` (ESP-IDF default config) + `tools/corpus/spiffs_writer.py`, **CI-proven
  byte-identical to ESP-IDF v5.3.1 `spiffsgen.py`** (fetched at the pinned tag in CI).
  Files carry exact dump segments (one per 251-byte data page). Unrecognised SPIFFS →
  `FS_SPIFFS_UNRECOGNISED` anomaly + raw string sweep of the partition.
- `fs/littlefs.py` via littlefs-python 0.19.0; tries block sizes 4096/512/1024/2048/8192,
  reports which mounted; never lets the library format the buffer (it does so on
  `mount=True` failure — found by reading its source). Round-trip tests (nested dirs,
  empty and binary files, two block sizes) run in CI.
- `coredump.py`: empty / binary (task count from header, bounded) / ELF / unknown.
- Context dispatch for FS + coredump; per-partition entropy; likely-encryption skip.
- Rules (one file each): PT.MD5_MISMATCH, PT.OVERLAP, PT.OUT_OF_BOUNDS,
  IMG.CHECKSUM_BAD, IMG.SHA256_BAD, IMG.NO_APP_DESC, IMG.UNKNOWN_BUILD,
  IMG.SLOT_DIVERGENCE, OTA.ROLLBACK_OR_DOWNGRADE, OTA.PENDING_VERIFY,
  OTA.INVALID_ACTIVE, FS.SUSPICIOUS_FILE, CORE.PRESENT, SEC.NO_FLASH_ENCRYPTION,
  SEC.NO_SECURE_BOOT, plus SEC.FLASH_ENCRYPTION_LIKELY (info) and PARSE.ANOMALY (low,
  every parser anomaly not owned by a dedicated rule). All with positive + negative tests.
- Fuzz/robustness harness covers SPIFFS, LittleFS, coredump and full `build_context`.

**Tests**: CI 177 passed / 0 skipped; local 158 passed / 5 skipped.

**Design decisions**
- OTA.INVALID_ACTIVE: the bootloader never *selects* an INVALID/ABORTED entry, so the
  rule fires when (a) the highest-seq otadata entry is INVALID/ABORTED (latest OTA
  rejected) or (b) the slot that will be selected has no image / fails checksum/SHA.
- IMG.UNKNOWN_BUILD hashes the image bytes `[0:image_length]` (incl. checksum and
  appended digest); `--baseline` files are hashed the same way.
- FS.SUSPICIOUS_FILE follows the spec literally ("any file triggering a SEC.* rule"),
  so a file containing only a URL is also flagged (reason `content:url`).

**CLAUDE.md corrections/additions**: SPIFFS layout, LittleFS formatting hazard,
coredump header, Secure Boot V2 version 0x03 (ECDSA).

**Known gaps**: SPIFFS deleted-page semantics are an assumption (spiffsgen only writes
fresh images); LittleFS file offsets come from content search; ELF coredump prefix
layout not verified against a real device dump.
