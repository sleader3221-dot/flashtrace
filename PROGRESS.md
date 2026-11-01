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
