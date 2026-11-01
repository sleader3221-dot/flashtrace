"""Benchmark corpus generator: 10 synthetic 4 MB ESP32 dumps with planted conditions.

Each device directory gets ``dump.bin``, ``ground_truth.json`` and optional
``baselines/*.bin``. Generation is deterministic (fixed seeds, fixed test key).
Component images are merged with ``esptool merge-bin`` (v5) / ``merge_bin`` (v4)
when esptool is installed, else with an equivalent internal merge; CI checks both
produce identical bytes. All secrets are obviously fake test values.

Usage: python -m tools.corpus.generate OUT_DIR
"""

from __future__ import annotations

import importlib.util
import json
import random
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from flashtrace.nvs import parse_nvs
from flashtrace.rules import load_rules
from tools.corpus.images import (
    BOOTLOADER_OFFSET,
    CLEAN_NVS_ROWS,
    DEFAULT_LAYOUT,
    app_desc,
    app_image,
    bootloader_image,
    otadata,
    otadata_entry,
    partition_table,
    signed,
)
from tools.corpus.nvs_writer import NvsWriter, erase
from tools.corpus.spiffs_writer import build_spiffs

FLASH = 4 * 1024 * 1024
CHIP = "esp32"
FAKE_AWS_KEY = "AKIAEXAMPLEFLASHTR01"  # 20 chars, documentation-style fake
FAKE_TOKEN = "tok_EXAMPLE_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z"
BENIGN_FILES = [
    ("/index.html", b"<!doctype html><title>Sensor</title><p>status: ok</p>\n"),
    ("/config.json", b'{"interval_s": 60, "units": "metric"}\n'),
]
TEST_KEY_SCALAR = int.from_bytes(b"flashtrace-corpus-test-key-only!", "big")


def test_private_key_pem() -> bytes:
    """Deterministic, obviously-test EC key (never used for anything real)."""
    key = ec.derive_private_key(TEST_KEY_SCALAR, ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass
class Device:
    name: str
    description: str
    must_fire: list[str]
    dont_care: list[str] = field(default_factory=list)
    components: dict[int, bytes] = field(default_factory=dict)
    baselines: dict[str, bytes] = field(default_factory=dict)
    post: str | None = None  # post-merge mutation id


def _nvs(rows: list[tuple[str, str, str, str]]) -> NvsWriter:
    return NvsWriter(0x4000).rows(rows)


def _base(
    *,
    a0: bytes | None = None,
    a1: bytes | None = None,
    ota: tuple[bytes | None, bytes | None] | None = None,
    nvs: bytes | None = None,
    spiffs_files: list[tuple[str, bytes]] | None = None,
    table: bytes | None = None,
) -> dict[int, bytes]:
    parts = {p.label: p for p in DEFAULT_LAYOUT}
    return {
        BOOTLOADER_OFFSET[CHIP]: bootloader_image(CHIP),
        0x8000: table if table is not None else partition_table(list(DEFAULT_LAYOUT)),
        parts["nvs"].offset: nvs if nvs is not None else _nvs(CLEAN_NVS_ROWS).to_bytes(),
        parts["otadata"].offset: otadata(ota or (otadata_entry(1, 2), otadata_entry(2, 2))),
        parts["ota_0"].offset: a0 if a0 is not None else signed(GOOD_0),
        parts["ota_1"].offset: a1 if a1 is not None else signed(GOOD_1),
        parts["spiffs"].offset: build_spiffs(spiffs_files or BENIGN_FILES, parts["spiffs"].size),
    }


GOOD_0 = app_image(CHIP, desc=app_desc(version="1.0.0", project_name="sensor_fw"), seed=0)
GOOD_1 = app_image(CHIP, desc=app_desc(version="1.1.0", project_name="sensor_fw"), seed=1)
POSTURE = "SEC.NO_FLASH_ENCRYPTION"


def devices() -> list[Device]:
    devs: list[Device] = []
    devs.append(
        Device(
            "clean_control",
            "Benign device: signed images, ota_1 active and VALID, NVS and SPIFFS without"
            " secrets. Only the inherent plaintext-flash posture finding is expected.",
            [POSTURE],
            components=_base(),
            baselines={"ota_0.bin": GOOD_0, "ota_1.bin": GOOD_1},
        )
    )
    wifi = _nvs(
        [
            *CLEAN_NVS_ROWS,
            ("nvs.net80211", "namespace", "", ""),
            ("sta.ssid", "data", "blob_sz_fill(32;0x00)", "CorpusLab-WiFi"),
            ("sta.pswd", "data", "blob_fill(64;0x00)", "example-wifi-passphrase"),
        ]
    ).to_bytes()
    devs.append(
        Device(
            "wifi_creds_in_nvs",
            "Station SSID and passphrase stored in nvs.net80211.",
            [POSTURE, "NVS.WIFI_CREDENTIALS"],
            components=_base(nvs=wifi),
        )
    )
    rows = [
        *CLEAN_NVS_ROWS,
        ("cloud", "namespace", "", ""),
        ("api_token", "data", "string", FAKE_TOKEN),
    ]
    live = _nvs(rows).to_bytes()
    erased = erase(live, parse_nvs(live, 0x9000, "nvs"), "cloud", "api_token")
    devs.append(
        Device(
            "deleted_token_in_nvs",
            "An API token was written to NVS and then erased (bitmap 0b00); bytes remain.",
            [POSTURE, "NVS.DELETED_SECRET"],
            components=_base(nvs=erased),
        )
    )
    aws = app_image(
        CHIP,
        desc=app_desc(version="1.1.0", project_name="sensor_fw"),
        seed=1,
        rodata=b"\x00aws_access_key_id\x00" + FAKE_AWS_KEY.encode() + b"\x00",
    )
    devs.append(
        Device(
            "hardcoded_aws_key_in_app",
            "AKIA-style access key ID embedded in ota_1 rodata; images are unsigned.",
            [POSTURE, "SEC.API_KEY", "SEC.NO_SECURE_BOOT"],
            components=_base(a0=GOOD_0, a1=aws),
        )
    )
    evil = app_image(CHIP, desc=app_desc(version="1.1.0", project_name="sensor_fw_mod"), seed=99)
    devs.append(
        Device(
            "backdoored_ota_slot",
            "ota_1 (active) carries a different project_name and a build not in the baseline set.",
            [POSTURE, "IMG.UNKNOWN_BUILD", "IMG.SLOT_DIVERGENCE"],
            components=_base(a1=signed(evil)),
            baselines={"ota_0.bin": GOOD_0, "ota_1.bin": GOOD_1},
        )
    )
    a0_rb = app_image(
        CHIP, desc=app_desc(version="1.0.0", project_name="sensor_fw", secure_version=1)
    )
    a1_rb = app_image(
        CHIP, desc=app_desc(version="1.1.0", project_name="sensor_fw", secure_version=2), seed=1
    )
    devs.append(
        Device(
            "forced_rollback",
            "ota_0 (secure_version 1) was re-selected (seq 3) over ota_1 (secure_version 2).",
            [POSTURE, "OTA.ROLLBACK_OR_DOWNGRADE"],
            dont_care=["IMG.SLOT_DIVERGENCE"],
            components=_base(
                a0=signed(a0_rb), a1=signed(a1_rb), ota=(otadata_entry(3, 2), otadata_entry(2, 2))
            ),
        )
    )
    devs.append(
        Device(
            "pending_verify_ota",
            "Active slot ota_1 is in ESP_OTA_IMG_PENDING_VERIFY.",
            [POSTURE, "OTA.PENDING_VERIFY"],
            components=_base(ota=(otadata_entry(1, 2), otadata_entry(2, 1))),
        )
    )
    devs.append(
        Device(
            "pem_private_key_in_spiffs",
            "PEM private key stored as /certs/device.key in SPIFFS.",
            [POSTURE, "SEC.PRIVATE_KEY", "FS.SUSPICIOUS_FILE"],
            components=_base(
                spiffs_files=[*BENIGN_FILES, ("/certs/device.key", test_private_key_pem())]
            ),
        )
    )
    table = bytearray(partition_table(list(DEFAULT_LAYOUT)))
    table[2 * 32 + 12 + 7] ^= 0x01  # flip one byte of the phy_init label after the MD5
    devs.append(
        Device(
            "corrupted_partition_md5",
            "One partition-table byte was altered after the MD5 entry was computed.",
            [POSTURE, "PT.MD5_MISMATCH"],
            components=_base(table=bytes(table)),
        )
    )
    devs.append(
        Device(
            "encrypted_flash_simulated",
            "Partition table, NVS, otadata and both app slots overwritten with random bytes.",
            ["SEC.FLASH_ENCRYPTION_LIKELY"],
            components=_base(),
            post="encrypt",
        )
    )
    return devs


def internal_merge(components: dict[int, bytes], size: int = FLASH) -> bytes:
    out = bytearray(b"\xff" * size)
    for off, blob in sorted(components.items()):
        out[off : off + len(blob)] = blob
    return bytes(out)


def esptool_merge(components: dict[int, bytes], size: int = FLASH) -> bytes | None:
    """Merge with the installed esptool (merge-bin for v5, merge_bin for v4)."""
    spec = importlib.util.find_spec("esptool")
    if spec is None:
        return None
    import esptool  # noqa: PLC0415

    major = int(str(getattr(esptool, "__version__", "0")).split(".")[0])
    with tempfile.TemporaryDirectory() as tmp:
        args: list[str] = []
        for off, blob in sorted(components.items()):
            p = Path(tmp) / f"{off:#x}.bin"
            p.write_bytes(blob)
            args += [hex(off), str(p)]
        out = Path(tmp) / "merged.bin"
        mb = size // (1024 * 1024)
        if major >= 5:
            cmd = ["--chip", CHIP, "merge-bin", "-o", str(out), "--pad-to-size", f"{mb}MB"]
        else:
            cmd = ["--chip", CHIP, "merge_bin", "-o", str(out), "--fill-flash-size", f"{mb}MB"]
        proc = subprocess.run(
            [sys.executable, "-m", "esptool", *cmd, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"esptool merge failed: {proc.stdout}{proc.stderr}")
        return out.read_bytes()


def build_device(dev: Device, use_esptool: bool = True) -> tuple[bytes, str]:
    merged = esptool_merge(dev.components) if use_esptool else None
    tool = "esptool"
    if merged is None:
        merged = internal_merge(dev.components)
        tool = "internal"
    if dev.post == "encrypt":
        buf = bytearray(merged)
        rng = random.Random(0xE7C)
        buf[0x8000:0x310000] = rng.randbytes(0x310000 - 0x8000)
        merged = bytes(buf)
    return merged, tool


def generate(out_dir: Path, use_esptool: bool = True) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    all_rules = sorted(load_rules())
    written: list[Path] = []
    for dev in devices():
        d = out_dir / dev.name
        d.mkdir(exist_ok=True)
        dump, tool = build_device(dev, use_esptool)
        (d / "dump.bin").write_bytes(dump)
        base_files = []
        if dev.baselines:
            (d / "baselines").mkdir(exist_ok=True)
            for name, blob in dev.baselines.items():
                (d / "baselines" / name).write_bytes(blob)
                base_files.append(f"baselines/{name}")
        forbidden = [r for r in all_rules if r not in dev.must_fire and r not in dev.dont_care]
        gt = {
            "device": dev.name,
            "description": dev.description,
            "chip": CHIP,
            "flash_size": len(dump),
            "merge_tool": tool,
            "baselines": base_files,
            "must_fire": sorted(dev.must_fire),
            "must_not_fire": forbidden,
            "dont_care": sorted(dev.dont_care),
        }
        (d / "ground_truth.json").write_text(json.dumps(gt, indent=2) + "\n")
        written.append(d)
    return written


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m tools.corpus.generate OUT_DIR", file=sys.stderr)
        return 2
    for d in generate(Path(args[0])):
        print(d)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
