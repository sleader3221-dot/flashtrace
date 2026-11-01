# FlashTrace report

- **Dump SHA-256:** `da345e3fd91c3dfc0ef943ca9623685f23a3f26263dc2872b947e780d41eef30`
- **Size:** 4194304 bytes
- **Chip:** esp32c3 (bootloader at `0x0`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.2.0
- **Secrets:** redacted

## Executive summary

3 findings; highest severity **high**. 1 high/critical finding(s) need attention:
- **high** `SEC.HARDCODED_CREDENTIAL` — Hardcoded credential (user=sensor) in app:ota_1

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 0 | 0 | 2 | 1 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| high | `SEC.HARDCODED_CREDENTIAL` | Hardcoded credential (user=sensor) in app:ota_1 | `0x19023e` +15 (ota_1) sha256 `d507dd2151c718d8…` | T0891 |
| medium | `SEC.MQTT_BROKER` | MQTT endpoint in app:ota_1 | `0x19022f` +61 (ota_1) sha256 `07bb2d498cd6e806…` | - |
| medium | `SEC.NO_FLASH_ENCRYPTION` | Flash contents are plaintext (no flash encryption) | `0x8000` +256 (-) sha256 `ef10d4e2fae05443…` | - |

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
