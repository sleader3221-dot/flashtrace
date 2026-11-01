# FlashTrace report

- **Dump SHA-256:** `3fa3f4becf42f5f3e3b0b1ea6cbcab6d1417cddd4dd5a67bbfda9f7077960e6e`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.2.0
- **Secrets:** redacted

## Executive summary

6 findings; highest severity **medium**.

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 5 | 0 | 1 | 0 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| medium | `SEC.NO_FLASH_ENCRYPTION` | Flash contents are plaintext (no flash encryption) | `0x8000` +256 (-) sha256 `ef10d4e2fae05443…` | - |
| info | `SEC.CERT` | Certificate in app:ota_1: CN=FlashTrace Test Root CA | `0x190228` +308 (ota_1) sha256 `530f865a0119db39…` | - |
| info | `SEC.URL` | URL in app:ota_1 | `0x19035d` +54 (ota_1) sha256 `ecda3e794565477e…` | - |
| info | `SEC.URL` | URL in app:ota_1 | `0x190394` +20 (ota_1) sha256 `197a7c8f20da9d0b…` | - |
| info | `SEC.URL` | URL in app:ota_1 | `0x1903a9` +43 (ota_1) sha256 `7c0405ac1e52c891…` | - |
| info | `SEC.URL` | URL in app:ota_1 | `0x1903d5` +46 (ota_1) sha256 `8140e307a1ec45e3…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|
| nvs | data | nvs | `0x9000` | 16384 | 0.13 |
| otadata | data | ota | `0xd000` | 8192 | 0.04 |
| phy_init | data | phy | `0xf000` | 4096 | 0.00 |
| ota_0 | app | ota_0 | `0x10000` | 1572864 | 0.02 |
| ota_1 | app | ota_1 | `0x190000` | 1572864 | 0.03 |
| spiffs | data | spiffs | `0x310000` | 983040 | 0.01 |

## Recovered deleted NVS entries

None.

## Device-reported timeline (untrusted)

| Value | Normalised (UTC) | Source |
|---|---|---|
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_0 (build time, timezone unknown) |
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_1 (build time, timezone unknown) |
