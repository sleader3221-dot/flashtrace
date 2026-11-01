"""Benchmark corpus generator: synthetic 4 MB ESP32-family dumps with planted conditions.

Each device directory gets ``dump.bin``, ``ground_truth.json`` and optional
``baselines/*.bin`` and ``keys/*`` (flash/NVS encryption keys, Secure Boot public key).
Generation is deterministic (fixed seeds, fixed test keys, RFC 6979 ECDSA). Devices that
need littlefs-python are only generated where it is installed (CI).
Component images are merged with ``esptool merge-bin`` (v5) / ``merge_bin`` (v4)
when esptool is installed, else with an equivalent internal merge; CI checks both
produce identical bytes. All secrets are obviously fake test values.

Usage: python -m tools.corpus.generate OUT_DIR
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import random
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from flashtrace.crypto import Scheme, flash_crypt, load_flash_key, sign_sbv2
from flashtrace.nvs import parse_nvs
from flashtrace.rules import load_rules
from tools.corpus.images import (
    BOOTLOADER_OFFSET,
    CLEAN_NVS_ROWS,
    DEFAULT_LAYOUT,
    LAYOUT_WITH_COREDUMP,
    Part,
    app_desc,
    app_image,
    bootloader_image,
    otadata,
    otadata_entry,
    partition_table,
    signed,
)
from tools.corpus.nvs_writer import NvsWriter, encrypt_nvs, erase, nvs_keys_image
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
    post: Callable[[bytes], bytes] | None = None  # post-merge mutation
    chip: str = CHIP
    keys: dict[str, bytes] = field(default_factory=dict)  # written to keys/<name>
    gt_extra: dict[str, object] = field(default_factory=dict)  # e.g. flash_key path


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
    chip: str = CHIP,
    layout: tuple[Part, ...] = DEFAULT_LAYOUT,
    extra: dict[str, bytes] | None = None,
) -> dict[int, bytes]:
    parts = {p.label: p for p in layout}
    comps = {
        BOOTLOADER_OFFSET[chip]: bootloader_image(chip),
        0x8000: table if table is not None else partition_table(list(layout)),
        parts["nvs"].offset: nvs if nvs is not None else _nvs(CLEAN_NVS_ROWS).to_bytes(),
        parts["otadata"].offset: otadata(ota or (otadata_entry(1, 2), otadata_entry(2, 2))),
        parts["ota_0"].offset: a0 if a0 is not None else signed(good(chip, 0)),
        parts["ota_1"].offset: a1 if a1 is not None else signed(good(chip, 1)),
    }
    if "spiffs" in parts:
        comps[parts["spiffs"].offset] = build_spiffs(
            spiffs_files or BENIGN_FILES, parts["spiffs"].size
        )
    for label, blob in (extra or {}).items():
        comps[parts[label].offset] = blob
    return comps


def good(chip: str, n: int, **desc: object) -> bytes:
    version = "1.0.0" if n == 0 else "1.1.0"
    d = {"version": version, "project_name": "sensor_fw", **desc}
    return app_image(chip, desc=app_desc(**d), seed=n)  # type: ignore[arg-type]


# ---- fixed test key material (never used for anything real) ----------------------
FLASH_KEY_XTS = bytes(range(0x40, 0x60))  # 256-bit AES-XTS key
FLASH_KEY_ESP32 = bytes(range(0xA0, 0xC0))  # 256-bit ESP32 key
NVS_KEY = bytes(range(0x10, 0x50))  # e_key || t_key
SB_KEY = ec.derive_private_key(
    int.from_bytes(b"flashtrace-secure-boot-test-key!", "big"), ec.SECP256R1()
)
SB_PUBKEY_PEM = SB_KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
COREDUMP_BIN = struct.pack("<IIIIII", 0x2000, 0x0003, 5, 0x15C, 2, 3) + b"\x00" * 0x200


def _test_ca_der() -> bytes:
    key = ec.derive_private_key(
        int.from_bytes(b"flashtrace-test-ca-key-material!", "big"), ec.SECP256R1()
    )
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FlashTrace Test Root CA")])
    t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(t0)
        .not_valid_after(t0 + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256(), ecdsa_deterministic=True)
    )
    return cert.public_bytes(serialization.Encoding.DER)


NEGATIVE_RODATA = (
    b"\x00" + _test_ca_der() + b"\x00"
    b"https://docs.espressif.com/projects/esp-idf/en/latest/\x00"
    b"http://pool.ntp.org/\x00https://github.com/espressif/esp-idf/issues\x00"
    b"https://ota.example.com/firmware/sensor_fw.bin\x00"
    b"sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\x00"
    b"favicon=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==\x00"
    b"user_agent=FlashTraceSensor/1.1.0 (ESP-IDF v5.3.1)\x00"
)


def _littlefs_image() -> bytes | None:
    if importlib.util.find_spec("littlefs") is None:
        return None
    import littlefs  # noqa: PLC0415

    fs = littlefs.LittleFS(block_size=4096, block_count=0xF0000 // 4096)
    fs.makedirs("/config", exist_ok=True)
    fs.makedirs("/scripts", exist_ok=True)
    for path, data in (
        ("/config/app.json", b'{"interval_s": 60}\n'),
        ("/scripts/update.sh", b"#!/bin/sh\nreboot\n"),
    ):
        with fs.open(path, "wb") as fh:
            fh.write(data)
    return bytes(fs.context.buffer)


def _random_overlay(dump: bytes) -> bytes:
    buf = bytearray(dump)
    rng = random.Random(0xE7C)
    buf[0x8000:0x310000] = rng.randbytes(0x310000 - 0x8000)
    return bytes(buf)


def _flash_encrypt(
    scheme: Scheme, raw_key: bytes, layout: tuple[Part, ...], boot_start: int
) -> Callable[[bytes], bytes]:
    """Encrypt exactly the regions flash encryption covers (mirrors flashtrace.keys)."""
    key = load_flash_key(raw_key, scheme)

    def post(dump: bytes) -> bytes:
        buf = bytearray(dump)
        regions = [(boot_start, 0x8000 - boot_start), (0x8000, 0xC00)]
        for prt in layout:
            covered = prt.type == 0 or (prt.type == 1 and prt.subtype in (0x00, 0x04))
            is_nvs = prt.type == 1 and prt.subtype == 0x02
            if (covered or prt.flags & 1) and not is_nvs:
                regions.append((prt.offset, prt.size))
        for off, n in regions:
            buf[off : off + n] = flash_crypt(
                bytes(buf[off : off + n]), off, key, scheme, decrypt=False
            )
        return bytes(buf)

    return post


GOOD_0 = good(CHIP, 0)
GOOD_1 = good(CHIP, 1)
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
            post=_random_overlay,
        )
    )
    # ---- expansion: encryption with keys, other chips, coredump, FS, negatives ----
    s3_layout = (
        Part("nvs", 1, 0x02, 0x9000, 0x4000),
        Part("otadata", 1, 0x00, 0xD000, 0x2000),
        Part("nvs_keys", 1, 0x04, 0xF000, 0x1000, flags=1),
        Part("ota_0", 0, 0x10, 0x10000, 0x180000),
        Part("ota_1", 0, 0x11, 0x190000, 0x180000),
        Part("spiffs", 1, 0x82, 0x310000, 0xF0000),
    )
    wifi_rows = [
        *CLEAN_NVS_ROWS,
        ("nvs.net80211", "namespace", "", ""),
        ("sta.ssid", "data", "blob_sz_fill(32;0x00)", "EncryptedLab-WiFi"),
        ("sta.pswd", "data", "blob_fill(64;0x00)", "example-encrypted-passphrase"),
    ]
    devs.append(
        Device(
            "esp32s3_encrypted_with_keys",
            "ESP32-S3 with AES-XTS flash encryption and NVS encryption (key in the flash-"
            "encrypted nvs_keys partition); Wi-Fi credentials are only visible with the key.",
            ["SEC.FLASH_ENCRYPTION_LIKELY", "NVS.WIFI_CREDENTIALS"],
            chip="esp32s3",
            components=_base(
                chip="esp32s3",
                layout=s3_layout,
                nvs=encrypt_nvs(_nvs(wifi_rows).to_bytes(), NVS_KEY),
                extra={"nvs_keys": nvs_keys_image(NVS_KEY)},
            ),
            post=_flash_encrypt("aes-xts", FLASH_KEY_XTS, s3_layout, boot_start=0x0),
            keys={"flash_key.bin": FLASH_KEY_XTS},
            gt_extra={"flash_key": "keys/flash_key.bin"},
        )
    )
    aws_enc = app_image(
        CHIP,
        desc=app_desc(version="1.1.0", project_name="sensor_fw"),
        seed=1,
        rodata=b"\x00aws_access_key_id\x00" + FAKE_AWS_KEY.encode() + b"\x00",
    )
    devs.append(
        Device(
            "esp32_encrypted_esp32_scheme",
            "Original ESP32 flash encryption (tweaked AES, FLASH_CRYPT_CONFIG 0xF); an AWS key"
            " in the encrypted ota_1 is only visible with the key.",
            ["SEC.FLASH_ENCRYPTION_LIKELY", "SEC.API_KEY"],
            dont_care=["SEC.NO_SECURE_BOOT"],
            components=_base(a1=aws_enc),
            post=_flash_encrypt("esp32", FLASH_KEY_ESP32, DEFAULT_LAYOUT, boot_start=0x1000),
            keys={"flash_key.bin": FLASH_KEY_ESP32},
            gt_extra={"flash_key": "keys/flash_key.bin", "flash_crypt_conf": 0xF},
        )
    )
    mqtt_rodata = b"\x00broker\x00mqtts://sensor:Pa55-Example-01@iot.example.com:8883/telemetry\x00"
    devs.append(
        Device(
            "esp32c3_mqtt_credentials",
            "ESP32-C3 firmware with an MQTT broker URI that embeds a username and password.",
            [POSTURE, "SEC.MQTT_BROKER", "SEC.HARDCODED_CREDENTIAL"],
            chip="esp32c3",
            components=_base(
                chip="esp32c3",
                a1=signed(
                    app_image(
                        "esp32c3",
                        desc=app_desc(version="1.1.0", project_name="sensor_fw"),
                        seed=1,
                        rodata=mqtt_rodata,
                    )
                ),
            ),
        )
    )
    devs.append(
        Device(
            "coredump_after_crash",
            "A binary-format coredump (5 tasks) was saved after a crash.",
            [POSTURE, "CORE.PRESENT"],
            components=_base(layout=LAYOUT_WITH_COREDUMP, extra={"coredump": COREDUMP_BIN}),
        )
    )
    lfs = _littlefs_image()
    if lfs is not None:
        lfs_layout = (*DEFAULT_LAYOUT[:-1], Part("storage", 1, 0x83, 0x310000, 0xF0000))
        devs.append(
            Device(
                "littlefs_with_script",
                "LittleFS partition holding a shell script next to benign config files.",
                [POSTURE, "FS.SUSPICIOUS_FILE"],
                components=_base(layout=lfs_layout, extra={"storage": lfs}),
            )
        )
    devs.append(
        Device(
            "ca_bundle_and_urls_negative",
            "Hard negative: firmware with an embedded DER CA certificate, many documentation"
            " URLs, a base64 data: URI and hex digests. Only informational findings may fire.",
            [POSTURE, "SEC.CERT", "SEC.URL"],
            components=_base(
                a1=signed(
                    app_image(
                        CHIP,
                        desc=app_desc(version="1.1.0", project_name="sensor_fw"),
                        seed=1,
                        rodata=NEGATIVE_RODATA,
                    )
                )
            ),
        )
    )
    signed_good_1 = sign_sbv2(GOOD_1, SB_KEY, deterministic=True)
    evil_1 = app_image(
        CHIP,
        desc=app_desc(version="1.1.0", project_name="sensor_fw"),
        seed=1,
        rodata=b"\x00telnetd-enabled\x00",
    )
    devs.append(
        Device(
            "signed_ota_tampered",
            "Both slots carry Secure Boot V2 signatures from the device key, but ota_1 was"
            " modified after signing (checksum and SHA-256 recomputed by the attacker).",
            [POSTURE, "IMG.SIGNATURE_INVALID"],
            components=_base(
                a0=sign_sbv2(GOOD_0, SB_KEY, deterministic=True),
                a1=evil_1 + b"\xff" * (-len(evil_1) % 4096) + signed_good_1[-4096:],
            ),
            keys={"sb_pubkey.pem": SB_PUBKEY_PEM},
            gt_extra={"sb_pubkey": "keys/sb_pubkey.pem"},
        )
    )
    rot = _nvs(
        [
            *CLEAN_NVS_ROWS,
            ("mqtt", "namespace", "", ""),
            ("mqtt_pass", "data", "string", "Old-Example-Pass-2024"),
            ("mqtt_pass", "data", "string", "New-Example-Pass-2025"),
        ]
    ).to_bytes()
    rot = erase(rot, parse_nvs(rot, 0x9000, "nvs"), "mqtt", "mqtt_pass", occurrence=0)
    devs.append(
        Device(
            "rotated_password_in_nvs",
            "An MQTT password was rotated; the previous value was erased but is still in flash.",
            [POSTURE, "NVS.DELETED_SECRET"],
            components=_base(nvs=rot),
        )
    )
    return devs


def internal_merge(components: dict[int, bytes], size: int = FLASH) -> bytes:
    out = bytearray(b"\xff" * size)
    for off, blob in sorted(components.items()):
        out[off : off + len(blob)] = blob
    return bytes(out)


def esptool_merge(
    components: dict[int, bytes], size: int = FLASH, chip: str = CHIP
) -> bytes | None:
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
            cmd = ["--chip", chip, "merge-bin", "-o", str(out), "--pad-to-size", f"{mb}MB"]
        else:
            cmd = ["--chip", chip, "merge_bin", "-o", str(out), "--fill-flash-size", f"{mb}MB"]
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
    merged = esptool_merge(dev.components, chip=dev.chip) if use_esptool else None
    tool = "esptool"
    if merged is None:
        merged = internal_merge(dev.components)
        tool = "internal"
    if dev.post is not None:
        merged = dev.post(merged)
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
        if dev.keys:
            (d / "keys").mkdir(exist_ok=True)
            for name, blob in dev.keys.items():
                (d / "keys" / name).write_bytes(blob)
        forbidden = [r for r in all_rules if r not in dev.must_fire and r not in dev.dont_care]
        gt = {
            "device": dev.name,
            "description": dev.description,
            "chip": dev.chip,
            "flash_size": len(dump),
            "merge_tool": tool,
            "baselines": base_files,
            "must_fire": sorted(dev.must_fire),
            "must_not_fire": forbidden,
            "dont_care": sorted(dev.dont_care),
            **dev.gt_extra,
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
