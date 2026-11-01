"""Synthetic, spec-valid ESP32-family flash artefacts for tests and the benchmark corpus.

Everything here is written from the *reference implementations*, not from the
FlashTrace parsers, so tests catch parser bugs instead of mirroring them:

* app images: esptool v5.1.0 ``bin_image.ESP32FirmwareImage`` (header, extended
  header, segments, 16-byte-aligned XOR checksum seeded 0xEF, appended SHA-256),
  validated in ``test_esptool_crosscheck.py`` by running ``esptool image-info``.
* ``esp_app_desc_t``: ESP-IDF ``esp_app_desc.h`` / esptool ``_parse_app_info``.
* partition tables: ESP-IDF ``gen_esp32part.py`` ``PartitionTable.to_binary``.
* otadata: ESP-IDF ``otatool.py`` (``binascii.crc32(seq, 0xFFFFFFFF)``).

Dumps are generated in memory at test time; nothing large is committed.
"""

from __future__ import annotations

import binascii
import hashlib
import struct
from dataclasses import dataclass, field

from tools.corpus.nvs_writer import build_nvs

FLASH_4MB = 4 * 1024 * 1024

# esp_chip_id_t values
CHIP_ID = {"esp32": 0, "esp32s2": 2, "esp32c3": 5, "esp32s3": 9, "esp32c6": 13}
BOOTLOADER_OFFSET = {"esp32": 0x1000, "esp32s2": 0x1000, "esp32c3": 0, "esp32s3": 0, "esp32c6": 0}

# (DROM, DRAM, IRAM, IROM) load addresses inside each chip's esptool MEMORY_MAP.
SEGMENT_ADDRS = {
    "esp32": (0x3F400020, 0x3FFB0000, 0x40080000, 0x400D0020),
    "esp32s2": (0x3F000020, 0x3FFB0000, 0x40020000, 0x40080020),
    "esp32s3": (0x3C000020, 0x3FC88000, 0x40374000, 0x42000020),
    "esp32c3": (0x3C000020, 0x3FC88000, 0x40380000, 0x42000020),
    "esp32c6": (0x42800020, 0x40800000, 0x40800400, 0x42000020),
}


def app_desc(
    *,
    version: str = "1.0.0",
    project_name: str = "flashtrace_fixture",
    time: str = "12:00:00",
    date: str = "Jan  1 2026",
    idf_ver: str = "v5.3.1",
    secure_version: int = 0,
    elf_sha256: bytes = b"\x11" * 32,
) -> bytes:
    def fixed(s: str, n: int) -> bytes:
        raw = s.encode()
        if len(raw) >= n:
            raise ValueError(f"{s!r} does not fit in {n} bytes")
        return raw.ljust(n, b"\x00")

    out = struct.pack("<II8s", 0xABCD5432, secure_version, b"\x00" * 8)
    out += fixed(version, 32) + fixed(project_name, 32) + fixed(time, 16) + fixed(date, 16)
    out += fixed(idf_ver, 32) + elf_sha256
    out += struct.pack("<HHB3s72s", 0, 0, 0, b"\x00" * 3, b"\x00" * 72)
    assert len(out) == 256
    return out


def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 4)


def app_image(
    chip: str = "esp32",
    *,
    desc: bytes | None = None,
    segments: list[tuple[int, bytes]] | None = None,
    hash_appended: bool = True,
    entry: int | None = None,
    corrupt_checksum: bool = False,
    corrupt_sha256: bool = False,
    seed: int = 0,
    rodata: bytes = b"",
) -> bytes:
    """Build an app image the way esptool ``elf2image`` lays it out (minus IROM alignment)."""
    drom, dram, iram, irom = SEGMENT_ADDRS[chip]
    if segments is None:
        filler = hashlib.sha256(f"{chip}-{seed}".encode()).digest()
        segments = [
            (
                drom,
                _pad4(
                    (desc if desc is not None else app_desc()) + b"rodata:" + filler * 8 + rodata
                ),
            ),
            (dram, _pad4(b"dram-init" + filler * 4)),
            (iram, _pad4(b"\x13\x00\x00\x00" * 64 + filler)),
            (irom, _pad4(b"text" + filler * 16)),
        ]
    out = bytearray(
        struct.pack(
            "<BBBBI",
            0xE9,
            len(segments),
            2,  # DIO
            0x20,  # 4MB, 40m
            entry if entry is not None else iram + 0x4,
        )
    )
    out += struct.pack(
        "<BBBBHBHH4sB",
        0xEE,  # wp_pin disabled
        0,
        0,
        0,
        CHIP_ID[chip],
        0,
        0,
        399,
        b"\x00" * 4,
        1 if hash_appended else 0,
    )
    checksum = 0xEF
    for addr, data in segments:
        out += struct.pack("<II", addr, len(data)) + data
        for b in data:
            checksum ^= b
    out += b"\x00" * (15 - len(out) % 16)
    out.append((checksum ^ 0xFF) if corrupt_checksum else checksum)
    if hash_appended:
        digest = bytearray(hashlib.sha256(out).digest())
        if corrupt_sha256:
            digest[0] ^= 0xFF
        out += digest
    return bytes(out)


def bootloader_image(chip: str = "esp32") -> bytes:
    _drom, dram, iram, _irom = SEGMENT_ADDRS[chip]
    segs = [(dram, _pad4(b"\x50" + b"bootloader-desc" * 6)), (iram, b"\x13\x00\x00\x00" * 128)]
    return app_image(chip, segments=segs)


def sig_block(version: int = 0x02) -> bytes:
    """Structurally shaped Secure Boot V2 block (magic, version, zero body). Not signed."""
    return bytes([0xE7, version]) + b"\x00" * (1216 - 2)


@dataclass(frozen=True)
class Part:
    label: str
    type: int
    subtype: int
    offset: int
    size: int
    flags: int = 0


def partition_table(parts: list[Part], *, md5: bool = True, corrupt_md5: bool = False) -> bytes:
    out = b"".join(
        struct.pack(
            "<2sBBLL16sL",
            b"\xaa\x50",
            p.type,
            p.subtype,
            p.offset,
            p.size,
            p.label.encode(),
            p.flags,
        )
        for p in parts
    )
    if md5:
        digest = bytearray(hashlib.md5(out).digest())  # noqa: S324
        if corrupt_md5:
            digest[0] ^= 0xFF
        out += b"\xeb\xeb" + b"\xff" * 14 + bytes(digest)
    assert len(out) < 0xC00
    return out + b"\xff" * (0xC00 - len(out))


def otadata_entry(seq: int, state: int = 0xFFFFFFFF, *, bad_crc: bool = False) -> bytes:
    crc = binascii.crc32(struct.pack("<I", seq), 0xFFFFFFFF) & 0xFFFFFFFF
    if bad_crc:
        crc ^= 0x1
    return struct.pack("<I20sII", seq, b"\xff" * 20, state, crc)


def otadata(entries: tuple[bytes | None, bytes | None]) -> bytes:
    out = bytearray(b"\xff" * 0x2000)
    for i, e in enumerate(entries):
        if e is not None:
            out[i * 0x1000 : i * 0x1000 + len(e)] = e
    return bytes(out)


DEFAULT_LAYOUT = (
    Part("nvs", 1, 0x02, 0x9000, 0x4000),
    Part("otadata", 1, 0x00, 0xD000, 0x2000),
    Part("phy_init", 1, 0x01, 0xF000, 0x1000),
    Part("ota_0", 0, 0x10, 0x10000, 0x180000),
    Part("ota_1", 0, 0x11, 0x190000, 0x180000),
    Part("spiffs", 1, 0x82, 0x310000, 0xF0000),
)


LAYOUT_WITH_COREDUMP = (
    *DEFAULT_LAYOUT[:-1],
    Part("spiffs", 1, 0x82, 0x310000, 0xE0000),
    Part("coredump", 1, 0x03, 0x3F0000, 0x10000),
)


def signed(image: bytes, version: int = 0x02) -> bytes:
    """Append a (structural) Secure Boot V2 signature sector after an image."""
    return image + b"\xff" * (-len(image) % 4096) + sig_block(version)


@dataclass
class DumpSpec:
    chip: str = "esp32"
    size: int = FLASH_4MB
    layout: tuple[Part, ...] = DEFAULT_LAYOUT
    table_offset: int = 0x8000
    apps: dict[str, bytes] = field(default_factory=dict)
    otadata: bytes | None = None
    corrupt_md5: bool = False
    data: dict[str, bytes] = field(default_factory=dict)  # raw bytes per partition label


def build_dump(spec: DumpSpec) -> bytes:
    dump = bytearray(b"\xff" * spec.size)

    def put(off: int, data: bytes) -> None:
        dump[off : off + len(data)] = data

    put(BOOTLOADER_OFFSET[spec.chip], bootloader_image(spec.chip))
    put(spec.table_offset, partition_table(list(spec.layout), corrupt_md5=spec.corrupt_md5))
    by_label = {p.label: p for p in spec.layout}
    for label, image in spec.apps.items():
        part = by_label[label]
        assert len(image) <= part.size
        put(part.offset, image)
    if spec.otadata is not None:
        put(by_label["otadata"].offset, spec.otadata)
    for label, blob in spec.data.items():
        part = by_label[label]
        assert len(blob) <= part.size, label
        put(part.offset, blob)
    return bytes(dump)


def default_dump(chip: str = "esp32") -> bytes:
    """Two OTA slots, ota_1 active (seq 2), both images valid."""
    return build_dump(
        DumpSpec(
            chip=chip,
            apps={
                "ota_0": app_image(chip, desc=app_desc(version="1.0.0"), seed=0),
                "ota_1": app_image(chip, desc=app_desc(version="1.1.0"), seed=1),
            },
            otadata=otadata((otadata_entry(1, 2), otadata_entry(2, 2))),
        )
    )


CLEAN_NVS_ROWS = [
    ("storage", "namespace", "", ""),
    ("boot_count", "data", "u32", "7"),
    ("device_name", "data", "string", "sensor-01"),
    ("calib", "data", "hex2bin", "0102030405060708"),
]


def clean_nvs() -> bytes:
    return build_nvs(CLEAN_NVS_ROWS, 0x4000)


def clean_dump(chip: str = "esp32") -> bytes:
    """A benign device: valid images, otadata, NVS without secrets, blank spiffs."""
    return build_dump(
        DumpSpec(
            chip=chip,
            apps={
                "ota_0": app_image(chip, desc=app_desc(version="1.0.0"), seed=0),
                "ota_1": app_image(chip, desc=app_desc(version="1.1.0"), seed=1),
            },
            otadata=otadata((otadata_entry(1, 2), otadata_entry(2, 2))),
            data={"nvs": clean_nvs()},
        )
    )
