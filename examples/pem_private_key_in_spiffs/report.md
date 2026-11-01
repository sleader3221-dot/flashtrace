# FlashTrace report

- **Dump SHA-256:** `ed7dd58190100617c9930b7a5d4deabc11bf11c6b0aab1895524c4fa1527f09f`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.1.0
- **Secrets:** redacted

## Executive summary

3 findings; highest severity **critical**. 1 high/critical finding(s) need attention:
- **critical** `SEC.PRIVATE_KEY` — Private key (PRIVATE KEY) in file:/certs/device.key

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 0 | 0 | 2 | 0 | 1 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| critical | `SEC.PRIVATE_KEY` | Private key (PRIVATE KEY) in file:/certs/device.key | `0x310605` +240 (spiffs) sha256 `9b75ed0fd4bdce55…` | - |
| medium | `FS.SUSPICIOUS_FILE` | Suspicious file /certs/device.key in spiffs | `0x310605` +241 (spiffs) sha256 `ce727fe4241cb554…` | - |
| medium | `SEC.NO_FLASH_ENCRYPTION` | Flash contents are plaintext (no flash encryption) | `0x8000` +256 (-) sha256 `ef10d4e2fae05443…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|
| nvs | data | nvs | `0x9000` | 16384 | 0.13 |
| otadata | data | ota | `0xd000` | 8192 | 0.04 |
| phy_init | data | phy | `0xf000` | 4096 | 0.00 |
| ota_0 | app | ota_0 | `0x10000` | 1572864 | 0.02 |
| ota_1 | app | ota_1 | `0x190000` | 1572864 | 0.02 |
| spiffs | data | spiffs | `0x310000` | 983040 | 0.02 |

## Recovered deleted NVS entries

None.

## Device-reported timeline (untrusted)

| Value | Normalised (UTC) | Source |
|---|---|---|
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_0 (build time, timezone unknown) |
| Jan  1 2026 12:00:00 | 2026-01-01T12:00:00+00:00 | app_desc.date+time of ota_1 (build time, timezone unknown) |
