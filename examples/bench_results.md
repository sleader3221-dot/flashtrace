| Rule | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `CORE.PRESENT` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `FS.SUSPICIOUS_FILE` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `IMG.SIGNATURE_INVALID` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `IMG.SLOT_DIVERGENCE` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `IMG.UNKNOWN_BUILD` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `NVS.DELETED_SECRET` | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `NVS.WIFI_CREDENTIALS` | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `OTA.PENDING_VERIFY` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `OTA.ROLLBACK_OR_DOWNGRADE` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `PT.MD5_MISMATCH` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.API_KEY` | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.CERT` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.FLASH_ENCRYPTION_LIKELY` | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.HARDCODED_CREDENTIAL` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.MQTT_BROKER` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.NO_FLASH_ENCRYPTION` | 14 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.NO_SECURE_BOOT` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.PRIVATE_KEY` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| `SEC.URL` | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Overall** | **37** | **0** | **0** | **1.00** | **1.00** | **1.00** |

Gate (recall ≥ 0.95, no forbidden rule, clean_control quiet): **PASS**
