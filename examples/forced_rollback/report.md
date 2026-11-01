# FlashTrace report

- **Dump SHA-256:** `070d157a56719a63e2d51494215ff2fe8a01b2cdc75121941e9a065443d92d1a`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.1.0
- **Secrets:** redacted

## Executive summary

3 findings; highest severity **high**. 1 high/critical finding(s) need attention:
- **high** `OTA.ROLLBACK_OR_DOWNGRADE` — Active slot ota_0 is older than ota_1: secure_version 1 < 2; version 1.0.0 < 1.1.0

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 0 | 0 | 2 | 1 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| high | `OTA.ROLLBACK_OR_DOWNGRADE` | Active slot ota_0 is older than ota_1: secure_version 1 < 2; version 1.0.0 < 1.1.0 | `0xd000` +32 (-) sha256 `13cc5b0e538adeed…` | - |
| medium | `IMG.SLOT_DIVERGENCE` | ota_0 and ota_1 diverge: newest OTA write carries the lower version | `0x10020` +256 (ota_0) sha256 `e474632dda4e3b3e…` | - |
| medium | `SEC.NO_FLASH_ENCRYPTION` | Flash contents are plaintext (no flash encryption) | `0x8000` +256 (-) sha256 `ef10d4e2fae05443…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|
| nvs | data | nvs | `0x9000` | 16384 | 0.13 |
| otadata | data | ota | `0xd000` | 8192 | 0.04 |
| phy_init | data | phy | `0xf000` | 4096 | 0.00 |
| ota_0 | app | ota_0 | `0x10000` | 1572864 | 0.02 |
| ota_1 | app | ota_1 | `0x190000` | 1572864 | 0.02 |
| spiffs | data | spiffs | `0x310000` | 983040 | 0.01 |

## Recovered deleted NVS entries

None.

## Device-reported timeline (untrusted)

| Value | Normalised (UTC) | Source |
|---|---|---|
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_0 (build time, timezone unknown) |
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_1 (build time, timezone unknown) |
