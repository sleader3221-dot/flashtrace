# Changelog

All notable changes to FlashTrace. Versions follow semantic versioning.

## 0.2.0 (unreleased)

### Added
- `--flash-key` / `--flash-crypt-conf`: analyse flash-encrypted dumps. FlashTrace decrypts
  exactly the regions ESP-IDF encrypts (bootloader, partition table, nvs_keys, otadata,
  app partitions, `encrypted`-flag partitions) with AES-XTS or the original ESP32 scheme,
  chosen automatically. Verified byte-for-byte against `espsecure` in CI.
- `--nvs-key`, or automatic use of a decrypted `nvs_keys` partition: NVS decryption.
  Verified against `esp-idf-nvs-partition-gen encrypt` in CI.
- `--sb-pubkey`: Secure Boot V2 signature verification (RSA-3072 PSS, ECDSA P-192/P-256/
  P-384) and the new `IMG.SIGNATURE_INVALID` rule. Verified against `espsecure sign-data`.
- `flashtrace explain` (optional, `pip install 'flashtrace[explain]'`): plain-language
  explanations of existing findings with Claude. Never creates or changes findings and
  refuses unredacted reports unless `--allow-revealed` is passed.
- Rule categories (`detection`, `integrity`, `posture`, `diagnostic`), shown in
  `docs/rules.md`.
- Benchmark corpus grows from 10 to 18 devices: AES-XTS and ESP32-scheme encrypted dumps
  (with keys), ESP32-S3 and ESP32-C3 firmware, a coredump, a LittleFS script, a signed
  image tampered after signing, a rotated password recoverable from NVS, and a hard
  negative (CA certificate, documentation URLs, base64 data URI).
- Release workflow: tag `vX.Y.Z` to test, build and publish to PyPI (trusted publishing)
  and create a GitHub release.

### Changed
- Posture rules (`SEC.NO_FLASH_ENCRYPTION`, `SEC.NO_SECURE_BOOT`,
  `SEC.FLASH_ENCRYPTION_LIKELY`) keep their severity and are excluded from the
  benchmark's "unexpected finding on clean_control" check by category; they are still
  scored through ground truth.
- The flash-encryption heuristic measures entropy over the partition table's own 0xC00
  bytes; the previous 64 KB window missed real encrypted devices whose plaintext NVS
  follows the table.

### Fixed
- `SEC.API_KEY` no longer reports the base64 payload of `data:` URIs as a token.

## 0.1.0

First release: io, partition, app image, otadata, NVS (incl. deleted-entry recovery),
SPIFFS, LittleFS, coredump parsers; 25 rules; SQLite evidence store; JSON/Markdown/HTML
reports; `analyze`, `diff`, `bench`; 10-device benchmark with a CI gate.
