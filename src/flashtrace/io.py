"""Dump loading, chip / bootloader-offset detection and entropy.

Chip IDs and bootloader offsets were checked against esptool v5.1.0
(``esptool/targets/*.py``: ``IMAGE_CHIP_ID``, ``BOOTLOADER_FLASH_OFFSET``) and
ESP-IDF v5.3.1 ``esp_app_format.h`` (``esp_chip_id_t``).
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from flashtrace.model import Anomaly, ByteSource

IMAGE_MAGIC = 0xE9
MAX_DUMP_SIZE = 128 * 1024 * 1024  # refuse to slurp absurdly large files

# esp_chip_id_t -> esptool chip name
CHIP_IDS: dict[int, str] = {
    0x0000: "esp32",
    0x0002: "esp32s2",
    0x0005: "esp32c3",
    0x0009: "esp32s3",
    0x000C: "esp32c2",
    0x000D: "esp32c6",
    0x0010: "esp32h2",
    0x0011: "esp32c5",  # C5 beta3 (MPW)
    0x0012: "esp32p4",
    0x0017: "esp32c5",  # C5 MP
}

# Where the ROM loads the second-stage bootloader from, per chip.
BOOTLOADER_OFFSETS: dict[str, int] = {
    "esp32": 0x1000,
    "esp32s2": 0x1000,
    "esp32s3": 0x0,
    "esp32c2": 0x0,
    "esp32c3": 0x0,
    "esp32c6": 0x0,
    "esp32h2": 0x0,
    "esp32c5": 0x2000,
    "esp32p4": 0x2000,
}

CANDIDATE_BOOTLOADER_OFFSETS: tuple[int, ...] = (0x0, 0x1000, 0x2000)


class DumpTooLargeError(ValueError):
    pass


def load_dump(path: str | Path, max_size: int = MAX_DUMP_SIZE) -> bytes:
    p = Path(path)
    size = p.stat().st_size
    if size > max_size:
        raise DumpTooLargeError(f"{p} is {size} bytes (> {max_size})")
    return p.read_bytes()


def shannon_entropy(data: ByteSource) -> float:
    """Shannon entropy in bits/byte (0.0 for empty input)."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(bytes(data))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass(frozen=True)
class ChipDetection:
    chip: str | None  # None when chip_id is unknown
    chip_id: int
    bootloader_offset: int
    consistent: bool  # bootloader found at the offset the chip's ROM expects
    anomalies: tuple[Anomaly, ...] = field(default_factory=tuple)


def _plausible_image_header(dump: memoryview, off: int) -> int | None:
    """Return chip_id if a plausible app/bootloader image header sits at ``off``."""
    if off < 0 or off + 24 > len(dump):
        return None
    magic, seg_count = dump[off], dump[off + 1]
    if magic != IMAGE_MAGIC or not 1 <= seg_count <= 16:
        return None
    hash_appended = dump[off + 23]
    if hash_appended not in (0, 1):
        return None
    (chip_id,) = struct.unpack_from("<H", dump, off + 12)
    return int(chip_id)


def detect_chip(dump: ByteSource) -> ChipDetection | None:
    """Find the second-stage bootloader and identify the chip from its header.

    Scans 0x0, 0x1000 and 0x2000 for an image header. Returns ``None`` if no
    plausible header exists (e.g. encrypted or blank flash).
    """
    mv = memoryview(dump)
    for off in CANDIDATE_BOOTLOADER_OFFSETS:
        chip_id = _plausible_image_header(mv, off)
        if chip_id is None:
            continue
        chip = CHIP_IDS.get(chip_id)
        anomalies: list[Anomaly] = []
        if chip is None:
            anomalies.append(
                Anomaly(
                    "UNKNOWN_CHIP_ID",
                    f"bootloader image at {off:#x} has unknown chip_id {chip_id:#06x}",
                    off + 12,
                    2,
                    {"chip_id": chip_id},
                )
            )
            consistent = False
        else:
            consistent = BOOTLOADER_OFFSETS[chip] == off
            if not consistent:
                anomalies.append(
                    Anomaly(
                        "BOOTLOADER_OFFSET_MISMATCH",
                        f"{chip} bootloader expected at {BOOTLOADER_OFFSETS[chip]:#x},"
                        f" found at {off:#x}",
                        off,
                        24,
                        {"chip": chip, "expected": BOOTLOADER_OFFSETS[chip], "found": off},
                    )
                )
        return ChipDetection(chip, chip_id, off, consistent, tuple(anomalies))
    return None
