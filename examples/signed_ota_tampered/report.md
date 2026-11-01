# FlashTrace report

- **Dump SHA-256:** `9148a6083cc4e11d7e6441f34167188e9a631c449aa714b63ed9fe44b9795853`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.2.0
- **Secrets:** redacted

## Executive summary

2 findings; highest severity **high**. 1 high/critical finding(s) need attention:
- **high** `IMG.SIGNATURE_INVALID` — ota_1: not signed by the supplied key (block 0: image digest mismatch)

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 0 | 0 | 1 | 1 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| high | `IMG.SIGNATURE_INVALID` | ota_1: not signed by the supplied key (block 0: image digest mismatch) | `0x191000` +1216 (ota_1) sha256 `d1902e6a957b2809…` | - |
| medium | `SEC.NO_FLASH_ENCRYPTION` | Flash contents are plaintext (no flash encryption) | `0x8000` +256 (-) sha256 `ef10d4e2fae05443…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|
| nvs | data | nvs | `0x9000` | 16384 | 0.13 |
| otadata | data | ota | `0xd000` | 8192 | 0.04 |
| phy_init | data | phy | `0xf000` | 4096 | 0.00 |
| ota_0 | app | ota_0 | `0x10000` | 1572864 | 0.03 |
| ota_1 | app | ota_1 | `0x190000` | 1572864 | 0.02 |
| spiffs | data | spiffs | `0x310000` | 983040 | 0.01 |

## Recovered deleted NVS entries

None.

## Device-reported timeline (untrusted)

| Value | Normalised (UTC) | Source |
|---|---|---|
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_0 (build time, timezone unknown) |
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_1 (build time, timezone unknown) |
