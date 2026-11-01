# FlashTrace report

- **Dump SHA-256:** `25d989c0e9698dbecc3ac00127a8af766b4d23dc86a0bc8c886a002cbef70c60`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.2.0
- **Secrets:** redacted
- **Decrypted view:** flash scheme `esp32`, NVS none; evidence hashes refer to the decrypted bytes (view SHA-256 `7f8cf8f835dca7aceb6e356cfcd2aebb08abfbf9fd81bb6dc501528bf764aed3`)

## Executive summary

2 findings; highest severity **high**. 1 high/critical finding(s) need attention:
- **high** `SEC.API_KEY` — AWS access key ID in app:ota_1

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 1 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| high | `SEC.API_KEY` | AWS access key ID in app:ota_1 | `0x19023a` +20 (ota_1) sha256 `f666d85146d001a8…` | - |
| info | `SEC.FLASH_ENCRYPTION_LIKELY` | Flash encryption enabled (esp32); analysed with supplied key | `0x8000` +3072 (-) sha256 `14d756b68b76ead4…` | - |

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
