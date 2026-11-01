"""Validate generated app images and the FlashTrace parser against official esptool.

Runs ``python -m esptool image-info <file>`` (esptool v5 CLI; output format read
from esptool v5.1.0 ``esptool/cmds.py::_print_image_info``) and checks that
esptool accepts our fixtures and agrees with ``parse_app_image`` field by field.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from flashtrace.appimage import AppImage, parse_app_image
from flashtrace.partition import parse_partition_table, partition_slice
from tests.conftest import require_module
from tests.fixtures.generator import CHIP_ID, app_desc, app_image, default_dump

require_module("esptool")

SEG_ROW = re.compile(r"^\s*(\d+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s", re.M)


def esptool_image_info(path: Path) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "esptool", "image-info", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def field(out: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}: (.*)$", out, re.M)
    assert m, f"{name!r} missing from esptool output:\n{out}"
    return m.group(1).strip()


def assert_agrees(out: str, img: AppImage) -> None:
    assert img.header is not None and img.app_desc is not None
    hdr, desc = img.header, img.app_desc
    assert int(field(out, "Segments")) == len(img.segments)
    chip_line = field(out, "Chip ID")
    assert chip_line.startswith(f"{hdr.chip_id} (") and "Unknown" not in chip_line
    assert int(field(out, "Entry point"), 16) == hdr.entry_addr
    assert field(out, "Flash size") == "4MB"
    assert field(out, "Flash mode") == "DIO"
    rows = [tuple(int(x, 0) for x in r) for r in SEG_ROW.findall(out)]
    assert rows == [
        (s.index, s.data_len, s.load_addr, s.header_offset - img.offset) for s in img.segments
    ]
    assert field(out, "Checksum") == f"{img.checksum_stored:#04x} (valid)"
    assert field(out, "Validation hash") == f"{img.sha256_stored} (valid)"
    assert field(out, "Project name") == desc.project_name
    assert field(out, "App version") == desc.version
    assert field(out, "Compile time") == f"{desc.date} {desc.time}"
    assert field(out, "ELF file SHA256") == desc.app_elf_sha256
    assert field(out, "ESP-IDF") == desc.idf_ver
    assert int(field(out, "Secure version")) == desc.secure_version


@pytest.mark.parametrize("chip", sorted(CHIP_ID))
def test_generated_image_matches_esptool(chip: str, tmp_path: Path) -> None:
    raw = app_image(
        chip,
        desc=app_desc(
            version=f"9.8.7-{chip}",
            project_name=f"xcheck_{chip}",
            idf_ver="v5.3.1",
            secure_version=3,
            elf_sha256=bytes(range(32)),
        ),
    )
    path = tmp_path / f"{chip}.bin"
    path.write_bytes(raw)
    out = esptool_image_info(path)
    img = parse_app_image(raw)
    assert img is not None and img.anomalies == ()
    assert_agrees(out, img)
    # esptool prints CHIP_NAME, e.g. "ESP32" / "ESP32-C3" (targets/*.py)
    name = "ESP32" if chip == "esp32" else f"ESP32-{chip[5:].upper()}"
    assert f"Detected image type: {name}" in out


def test_image_inside_dump_matches_esptool(tmp_path: Path) -> None:
    dump = default_dump()
    table = parse_partition_table(dump[0x8000:0x8C00], 0x8000)
    for entry in table.ota_apps:
        part = bytes(partition_slice(dump, entry))
        path = tmp_path / f"{entry.label}.bin"
        path.write_bytes(part)  # whole partition, trailing 0xFF included
        img = parse_app_image(part, entry.offset)
        assert img is not None
        assert_agrees(esptool_image_info(path), img)


def test_corrupt_checksum_agrees(tmp_path: Path) -> None:
    # generator appends a digest *of the corrupted bytes*, so only the checksum is bad
    raw = app_image(corrupt_checksum=True)
    path = tmp_path / "bad.bin"
    path.write_bytes(raw)
    out = esptool_image_info(path)
    img = parse_app_image(raw)
    assert img is not None and img.checksum_valid is False and img.sha256_valid is True
    assert field(out, "Checksum") == (
        f"{img.checksum_stored:#04x} (invalid - calculated {img.checksum_computed:#04x})"
    )
    assert field(out, "Validation hash") == f"{img.sha256_computed} (valid)"


def test_corrupt_digest_agrees(tmp_path: Path) -> None:
    raw = app_image(corrupt_sha256=True)
    path = tmp_path / "bad_sha.bin"
    path.write_bytes(raw)
    out = esptool_image_info(path)
    img = parse_app_image(raw)
    assert img is not None and img.sha256_valid is False
    assert field(out, "Validation hash") == f"{img.sha256_computed} (invalid)"
