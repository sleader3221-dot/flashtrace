# FlashTrace report

- **Dump SHA-256:** `3e8ed1549ac905aac7e51d1c4236cec5925a342dc294b2f5dc9b4b6f7003e41a`
- **Size:** 4194304 bytes
- **Chip:** esp32s3 (bootloader at `0x0`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.2.0
- **Secrets:** redacted
- **Decrypted view:** flash scheme `aes-xts`, NVS ['nvs']; evidence hashes refer to the decrypted bytes (view SHA-256 `11c0c39e3b245a76c7963e846ea87790d8b26a30d256409b59cb05cb303fe8c5`)

## Executive summary

2 findings; highest severity **high**. 1 high/critical finding(s) need attention:
- **high** `NVS.WIFI_CREDENTIALS` — Wi-Fi STA credentials in NVS (SSID 'EncryptedLab-WiFi')

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 1 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| high | `NVS.WIFI_CREDENTIALS` | Wi-Fi STA credentials in NVS (SSID 'EncryptedLab-WiFi') | `0x91a0` +32 (nvs) sha256 `5af0f670115c52f1…` | - |
| info | `SEC.FLASH_ENCRYPTION_LIKELY` | Flash encryption enabled (aes-xts); analysed with supplied key | `0x8000` +3072 (-) sha256 `c42483f68a002245…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|
| nvs | data | nvs | `0x9000` | 16384 | 0.40 |
| otadata | data | ota | `0xd000` | 8192 | 0.04 |
| nvs_keys | data | nvs_keys | `0xf000` | 4096 | 0.22 |
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
