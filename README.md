# FlashTrace

**Forensic triage for ESP32-family SPI flash dumps.**

An ESP32 flash dump holds the whole device: bootloader, partition table, both OTA
firmware slots, the NVS key/value store (Wi-Fi passwords, tokens, counters),
filesystems and crash dumps. Reading it by hand with a hex editor and five different
vendor tools is slow and easy to get wrong. FlashTrace parses the dump with
bounds-checked, deterministic parsers and produces an evidence-linked report of what
is on the device, which secrets are exposed, what changed between two dumps, and
whether the firmware shows signs of tampering or rollback.

## What makes it different

- **Evidence-linked findings.** Every finding cites the absolute offset, length,
  partition and SHA-256 of the exact supporting bytes. Secrets are redacted by default
  while their SHA-256 is kept, so a finding stays verifiable without disclosing it.
- **Deleted NVS recovery.** NVS entries that were erased (entry bitmap `0b00`) are
  parsed and reported as "deleted but recoverable", including chunked blobs.
- **OTA tamper and rollback detection.** Slot divergence, unknown builds against a
  baseline, secure_version/semver downgrades, PENDING_VERIFY and invalid active slots.
- **Validated against official tooling.** App images are cross-checked field by field
  with `esptool image-info`; FlashTrace's NVS and SPIFFS writers are proven
  byte-identical to `esp-idf-nvs-partition-gen` and ESP-IDF `spiffsgen.py` in CI.
- **Works on encrypted devices when you have the keys.** `--flash-key` decrypts flash
  encryption (AES-XTS or the original ESP32 scheme, detected automatically), `--nvs-key`
  or the device's own `nvs_keys` partition decrypts NVS, and `--sb-pubkey` verifies
  Secure Boot V2 signatures. All three are checked byte-for-byte against `espsecure`
  and `esp-idf-nvs-partition-gen` in CI.
- **Benchmark-validated.** A deterministic corpus of 18 devices with planted
  conditions (including encrypted, signed-then-tampered and hard-negative devices)
  scores every rule; CI fails on recall < 0.95 or any forbidden finding.
- **Never crashes on hostile input.** Malformed structures become `PARSE.ANOMALY`
  findings; every parser is fuzzed with Hypothesis.

## Quickstart

```bash
python -m pip install -e ".[dev]"
flashtrace analyze dump.bin --out report/ --format html --format json --format md
```

Open `report/report.html` (a single offline file; no external resources). The run
also writes `report/evidence.sqlite`.

## CLI

```
flashtrace analyze dump.bin [--chip auto|esp32|esp32s2|esp32s3|esp32c3|esp32c6]
                            [--baseline known_good_app.bin ...]
                            [--out report_dir/] [--format json|html|md ...]
                            [--reveal-secrets]
                            [--flash-key key.bin] [--flash-crypt-conf 0xF]
                            [--nvs-key nvs_keys.bin] [--sb-pubkey signing_pub.pem]
flashtrace diff dumpA.bin dumpB.bin --out diff_dir/
flashtrace bench corpus_dir/ --out bench_results.json
flashtrace explain report_dir/report.json --out explain_dir/   # optional, needs [explain]
```

With keys, analysis runs on a decrypted view of the dump: the report records the
original SHA-256, the decrypted regions and the scheme, and evidence hashes refer to the
decrypted bytes. `flashtrace explain` sends the (redacted) findings to Claude
(`claude-opus-5-5` by default; set `ANTHROPIC_API_KEY`) and writes a plain-language
explanation. It never creates or changes findings, and refuses reports produced with
`--reveal-secrets` unless `--allow-revealed` is given.

Exit codes: `0` no high/critical findings, `1` high/critical present (or bench gate
failed), `2` tool error. Without typer installed, `python -m flashtrace` provides the
same commands through an argparse fallback.

```bash
python -m tools.corpus.generate corpus/      # build the 10-device benchmark corpus
flashtrace bench corpus/ --out bench_results.json
```

## Architecture

```mermaid
flowchart LR
    D[dump.bin] --> IO[io: load, chip + bootloader offset, entropy]
    IO --> PT[partition table]
    PT --> APP[appimage<br/>header, segments, checksum,<br/>SHA-256, app_desc, SBv2 sig]
    PT --> OTA[otadata]
    PT --> NVS[nvs<br/>incl. ERASED entries]
    PT --> FS[fs: SPIFFS / LittleFS]
    PT --> CORE[coredump]
    APP & OTA & NVS & FS & CORE --> CTX[AnalysisContext<br/>+ scan regions mapped to dump offsets]
    CTX --> RULES[rules/ registry<br/>one module per rule]
    RULES --> ATT[ATT&CK for ICS map]
    ATT --> F[Findings + Evidence]
    F --> DB[(SQLite evidence store)]
    F --> REP[JSON / Markdown / HTML]
    CTX --> TL[device-reported timeline]
    TL --> DB & REP
```

## Benchmark

Generated from `examples/bench_results.json` (`python -m tools.make_examples`, then
`python -m tools.gen_docs`). Each device also lists every other rule as must-not-fire,
so the false-positive column covers the whole rule set. The LittleFS device needs
littlefs-python and is part of the CI run (18 devices); the committed table comes from a
run without it (17 devices).

<!-- BENCH:BEGIN -->
| Rule | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `CORE.PRESENT` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `FS.SUSPICIOUS_FILE` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `IMG.SIGNATURE_INVALID` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `IMG.SLOT_DIVERGENCE` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `IMG.UNKNOWN_BUILD` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `NVS.DELETED_SECRET` | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `NVS.WIFI_CREDENTIALS` | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `OTA.PENDING_VERIFY` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `OTA.ROLLBACK_OR_DOWNGRADE` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `PT.MD5_MISMATCH` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.API_KEY` | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.CERT` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.FLASH_ENCRYPTION_LIKELY` | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.HARDCODED_CREDENTIAL` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.MQTT_BROKER` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.NO_FLASH_ENCRYPTION` | 14 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.NO_SECURE_BOOT` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.PRIVATE_KEY` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.URL` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Overall** | **37** | **0** | **0** | **1.00** | **1.00** | **1.00** |

Gate (recall ≥ 0.95, no forbidden rule, clean_control quiet): **PASS**
<!-- BENCH:END -->

## Releasing

1. Update `CHANGELOG.md` and bump `version` in `pyproject.toml` and
   `src/flashtrace/__init__.py` (a test keeps them equal).
2. Once, on PyPI: add a trusted publisher for this repository, workflow `release.yml`,
   environment `pypi`.
3. Push a tag `vX.Y.Z`. `.github/workflows/release.yml` re-runs every check and the
   benchmark, builds the sdist and wheel, publishes to PyPI and creates a GitHub release.

## Example reports

`examples/<device>/report.{html,json,md}` for every corpus device, plus
`examples/diff_clean_vs_forced_rollback/`. Reports only; dumps are generated at test
time and never committed.

![HTML report screenshot](docs/report-screenshot.png)
*Screenshot of `examples/pem_private_key_in_spiffs/report.html` (synthetic corpus device).*

## Documentation

- [`docs/rules.md`](docs/rules.md) — every rule: severity, trigger, false-positive notes,
  ATT&CK for ICS mapping (generated).
- [`docs/report-schema.md`](docs/report-schema.md) — JSON report schema.
- [`CLAUDE.md`](CLAUDE.md) — design rules and verified on-flash format notes.
- [`PROGRESS.md`](PROGRESS.md) — development log, known gaps, items needing review.

## Limitations

- **Decryption needs the key.** Without `--flash-key` / `--nvs-key`, encrypted flash and
  NVS are detected and reported, and structural parsing is skipped. Keys must come from
  the device owner (eFuse readout or provisioning records); FlashTrace never attacks
  encryption.
- **Signature checks need the public key.** Without `--sb-pubkey`, Secure Boot V2
  blocks are only detected structurally. The bootloader's own signature is not checked.
- **Real-hardware validation is still open.** Formats are verified against the official
  tools' output, not against dumps read from physical devices.
- **SPIFFS assumptions.** Only the ESP-IDF default SPIFFS configuration is parsed (page
  256, block 4096, 32-byte names, 4-byte metadata). Deleted-page semantics are assumed.
- **LittleFS offsets.** File content is located by search; non-contiguous files are
  reported without a precise dump offset.
- **Wi-Fi blob layout.** Key names are verified; the exact blob layout written by the
  closed-source Wi-Fi driver is decoded defensively.
- **Synthetic benchmark.** The corpus is generated with official-tool-equivalent writers;
  results on real devices may differ. The heuristics (generic tokens, slot divergence)
  can produce false positives on real firmware.
- ATT&CK for ICS techniques are attached only where the mapping is unambiguous; most
  rules are marked `review: true` in `src/flashtrace/data/attck_ics_map.yaml`.

## Authorised use

FlashTrace is intended for analysing devices you own or are explicitly authorised to
examine: incident response, security research, CTFs and product security reviews.
Secrets are redacted by default; `--reveal-secrets` must be passed explicitly. Do not
use it to extract credentials from devices you are not authorised to examine.

## Licence

MIT. See [`LICENSE`](LICENSE).
