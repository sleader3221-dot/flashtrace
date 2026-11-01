# FlashTrace report

- **Dump SHA-256:** `cf47f7cab390968195c7931a229f4551ebf794dfa3e3f8ec351562678c6e872f`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.2.0
- **Secrets:** redacted

## Executive summary

2 findings; highest severity **high**. 1 high/critical finding(s) need attention:
- **high** `PT.MD5_MISMATCH` — Partition table MD5 mismatch: partition table MD5 does not match its entries

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 0 | 0 | 1 | 1 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| high | `PT.MD5_MISMATCH` | Partition table MD5 mismatch: partition table MD5 does not match its entries | `0x80c0` +32 (-) sha256 `4f373293d868ee6d…` | - |
| medium | `SEC.NO_FLASH_ENCRYPTION` | Flash contents are plaintext (no flash encryption) | `0x8000` +256 (-) sha256 `97e956d01f2cb916…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|
| nvs | data | nvs | `0x9000` | 16384 | 0.13 |
| otadata | data | ota | `0xd000` | 8192 | 0.04 |
| phy_iniu | data | phy | `0xf000` | 4096 | 0.00 |
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
