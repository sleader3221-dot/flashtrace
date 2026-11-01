import hashlib
import struct

import pytest

from flashtrace.appimage import parse_app_desc, parse_app_image
from tests.fixtures.generator import CHIP_ID, SEGMENT_ADDRS, app_desc, app_image, sig_block

BASE = 0x10000


def kinds(img: object) -> list[str]:
    return [a.kind for a in img.anomalies]  # type: ignore[attr-defined]


@pytest.mark.parametrize("chip", sorted(CHIP_ID))
def test_valid_image(chip: str) -> None:
    desc = app_desc(version="2.3.4", project_name="proj", idf_ver="v5.3.1", secure_version=7)
    raw = app_image(chip, desc=desc)
    img = parse_app_image(raw + b"\xff" * 4096, BASE)
    assert img is not None and img.header is not None
    assert img.anomalies == ()
    assert img.header.chip == chip and img.header.chip_id == CHIP_ID[chip]
    assert img.header.segment_count == 4 == len(img.segments)
    assert img.header.hash_appended == 1
    assert img.header.spi_size == 2 and img.header.spi_speed == 0 and img.header.spi_mode == 2
    assert img.image_length == len(raw)
    assert img.checksum_valid is True and img.sha256_valid is True
    assert img.sha256_stored == hashlib.sha256(raw[:-32]).hexdigest()
    assert img.checksum_offset == BASE + len(raw) - 33
    assert img.sha256_offset == BASE + len(raw) - 32
    assert (len(raw) - 32) % 16 == 0
    assert img.segments[0].load_addr == SEGMENT_ADDRS[chip][0]
    assert img.segments[0].header_offset == BASE + 24
    assert img.segments[0].data_offset == BASE + 32
    assert img.app_desc_segment == 0
    d = img.app_desc
    assert d is not None and d.offset == BASE + 32
    assert (d.version, d.project_name, d.idf_ver) == ("2.3.4", "proj", "v5.3.1")
    assert d.secure_version == 7
    assert (d.date, d.time) == ("Jan  1 2026", "12:00:00")
    assert d.app_elf_sha256 == "11" * 32
    assert img.signature_blocks == ()


def test_no_hash_appended() -> None:
    raw = app_image(hash_appended=False)
    img = parse_app_image(raw)
    assert img is not None and img.anomalies == ()
    assert img.image_length == len(raw) and len(raw) % 16 == 0
    assert img.sha256_valid is None and img.sha256_stored is None


def test_bad_checksum_and_sha() -> None:
    img = parse_app_image(app_image(corrupt_checksum=True))
    # the generator re-hashes after corrupting, so only the checksum is bad
    assert img is not None and img.checksum_valid is False and img.sha256_valid is True
    assert kinds(img) == ["IMG_CHECKSUM_BAD"]
    img = parse_app_image(app_image(corrupt_sha256=True))
    assert img is not None and img.checksum_valid is True and kinds(img) == ["IMG_SHA256_BAD"]


def test_tampered_segment_byte() -> None:
    raw = bytearray(app_image())
    raw[400] ^= 0x01
    img = parse_app_image(bytes(raw))
    assert img is not None and kinds(img) == ["IMG_CHECKSUM_BAD", "IMG_SHA256_BAD"]


def test_not_an_image() -> None:
    assert parse_app_image(b"") is None
    assert parse_app_image(b"\xff" * 100) is None


def test_truncations() -> None:
    raw = app_image()
    img = parse_app_image(raw[:10])
    assert img is not None and img.header is None and kinds(img) == ["IMG_TRUNCATED_HEADER"]
    img = parse_app_image(raw[:30])
    assert img is not None and kinds(img) == ["IMG_TRUNCATED_SEGMENT_HEADER"]
    img = parse_app_image(raw[:100])
    assert img is not None and kinds(img) == ["IMG_TRUNCATED_SEGMENT"] and not img.complete
    img = parse_app_image(raw[:-33])
    assert img is not None and kinds(img) == ["IMG_TRUNCATED_CHECKSUM"]
    img = parse_app_image(raw[:-5])
    assert img is not None and kinds(img) == ["IMG_TRUNCATED_DIGEST"]


def test_hostile_header_values() -> None:
    raw = bytearray(app_image())
    raw[1] = 200  # segment count
    raw[23] = 7  # hash_appended
    raw[12:14] = b"\xee\xee"
    img = parse_app_image(bytes(raw))
    assert img is not None
    assert {"IMG_TOO_MANY_SEGMENTS", "IMG_BAD_HASH_APPENDED", "IMG_UNKNOWN_CHIP_ID"} <= set(
        kinds(img)
    )
    huge = bytearray(app_image())
    struct.pack_into("<I", huge, 28, 0xFFFFFFF0)
    img = parse_app_image(bytes(huge))
    assert img is not None and "IMG_TRUNCATED_SEGMENT" in kinds(img)


def test_missing_app_desc() -> None:
    img = parse_app_image(app_image(desc=b"\x00" * 256))
    assert img is not None and img.app_desc is None and img.app_desc_segment is None


def test_app_desc_hidden_bytes() -> None:
    d = bytearray(app_desc(version="1.0"))
    d[16 + 10] = ord("X")  # after the NUL terminating "1.0" inside version[32]
    parsed = parse_app_desc(bytes(d))
    assert parsed is not None and parsed.version == "1.0"
    assert parsed.hidden_string_bytes == ("version",)
    img = parse_app_image(app_image(desc=bytes(d)))
    assert img is not None and "IMG_APP_DESC_HIDDEN_BYTES" in kinds(img)


@pytest.mark.parametrize("version", [0x02, 0x03])
def test_signature_blocks(version: int) -> None:
    raw = app_image()
    padded = raw + b"\xff" * (-len(raw) % 4096)
    img = parse_app_image(padded + sig_block(version) + sig_block(version), BASE)
    assert img is not None
    assert [(b.offset, b.version) for b in img.signature_blocks] == [
        (BASE + len(padded), version),
        (BASE + len(padded) + 1216, version),
    ]
    assert img.signature_blocks[0].scheme == {2: "RSA", 3: "ECDSA"}[version]
    # wrong version byte => not a sig block
    img = parse_app_image(padded + bytes([0xE7, 0x09]) + b"\x00" * 1214)
    assert img is not None and img.signature_blocks == ()
