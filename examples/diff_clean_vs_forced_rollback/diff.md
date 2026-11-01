# FlashTrace diff

- **A:** `53f71ba18313944b801bd6f78dbe7baaf17c1d181105d854ab947b5a7e1258f1` (4194304 bytes)
- **B:** `070d157a56719a63e2d51494215ff2fe8a01b2cdc75121941e9a065443d92d1a` (4194304 bytes)
- **Differences:** 6

| Severity | Rule | Finding | Evidence (first) | ATT&CK |
|---|---|---|---|---|
| info | `DIFF.PARTITION_CHANGED` | Partition 'ota_0' contents changed | `0x10000` +1572864 (ota_0) sha256 `c549ed148548b3e7…` | - |
| info | `DIFF.PARTITION_CHANGED` | Partition 'ota_1' contents changed | `0x190000` +1572864 (ota_1) sha256 `e963bf6d181d44ec…` | - |
| info | `DIFF.PARTITION_CHANGED` | Partition 'otadata' contents changed | `0xd000` +8192 (otadata) sha256 `b7e293bb607d3bdd…` | - |
| medium | `DIFF.APP_DESC` | App descriptor of ota_0 changed: secure_version | `0x10020` +256 (ota_0) sha256 `229e740ce001e5cf…` | - |
| medium | `DIFF.APP_DESC` | App descriptor of ota_1 changed: secure_version | `0x190020` +256 (ota_1) sha256 `9e7ea1917ea80511…` | - |
| low | `DIFF.OTA_STATE` | OTA selection/state changed | `0xd000` +8192 (-) sha256 `b7e293bb607d3bdd…` | - |
