# FlashTrace report

- **Dump SHA-256:** `00cf91481b2df786b71a12b4ded5b926ff66cbc9249f254cbc2422d7a11e891d`
- **Size:** 4194304 bytes
- **Chip:** esp32 (bootloader at `0x1000`)
- **Analysed:** 2026-01-01T00:00:00+00:00 with flashtrace 0.1.0
- **Secrets:** redacted

## Executive summary

Flash encryption is likely enabled: no partition table magic at 0x8000 and entropy 8.00 bits/byte > 7.5.
Structural parsing was skipped; findings are limited accordingly.

## Severity counts

| info | low | medium | high | critical |
|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 0 | 0 |

## Findings

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| info | `SEC.FLASH_ENCRYPTION_LIKELY` | Flash encryption likely enabled; structural parsing skipped | `0x8000` +4096 (-) sha256 `7f4aba7a146c09d5…` | - |

## Partitions

| Label | Type | Subtype | Offset | Size | Entropy |
|---|---|---|---|---:|---:|

## Recovered deleted NVS entries

None.

## Device-reported timeline (untrusted)

None.
