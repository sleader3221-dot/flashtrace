import os
from pathlib import Path

import pytest

from flashtrace.io import DumpTooLargeError, detect_chip, load_dump, shannon_entropy
from tests.fixtures.generator import BOOTLOADER_OFFSET, CHIP_ID, bootloader_image


def test_entropy() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\xff" * 4096) == 0.0
    assert shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)
    assert shannon_entropy(os.urandom(65536)) > 7.9


@pytest.mark.parametrize("chip", sorted(CHIP_ID))
def test_detect_chip(chip: str) -> None:
    dump = bytearray(b"\xff" * 0x10000)
    off = BOOTLOADER_OFFSET[chip]
    img = bootloader_image(chip)
    dump[off : off + len(img)] = img
    det = detect_chip(bytes(dump))
    assert det is not None
    assert (det.chip, det.chip_id, det.bootloader_offset) == (chip, CHIP_ID[chip], off)
    assert det.consistent and not det.anomalies


def test_detect_chip_offset_mismatch() -> None:
    dump = bytearray(b"\xff" * 0x10000)
    img = bootloader_image("esp32s3")
    dump[0x1000 : 0x1000 + len(img)] = img  # S3 bootloader where an ESP32 one would be
    det = detect_chip(bytes(dump))
    assert det is not None and det.chip == "esp32s3" and not det.consistent
    assert det.anomalies[0].kind == "BOOTLOADER_OFFSET_MISMATCH"


def test_detect_chip_unknown_id() -> None:
    img = bytearray(bootloader_image("esp32"))
    img[12:14] = b"\x34\x12"
    dump = b"\xff" * 0x1000 + bytes(img)
    det = detect_chip(dump)
    assert det is not None and det.chip is None and det.anomalies[0].kind == "UNKNOWN_CHIP_ID"


def test_detect_chip_blank_and_random() -> None:
    assert detect_chip(b"\xff" * 0x10000) is None
    assert detect_chip(b"") is None


def test_load_dump(tmp_path: Path) -> None:
    p = tmp_path / "d.bin"
    p.write_bytes(b"\x01\x02")
    assert load_dump(p) == b"\x01\x02"
    with pytest.raises(DumpTooLargeError):
        load_dump(p, max_size=1)
