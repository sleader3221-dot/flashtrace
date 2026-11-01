"""ESP32-family application / bootloader image parser.

Semantics follow esptool v5.1.0 ``esptool/bin_image.py`` (``ESP32FirmwareImage``)
and ESP-IDF v5.3.1 ``esp_app_format.h`` / ``esp_app_desc.h``:

* 8-byte header ``<BBBBI`` (magic 0xE9, segment_count, spi_mode,
  spi_speed(lo nibble)/spi_size(hi nibble), entry_addr).
* 16-byte extended header ``<BBBBHBHH4sB`` (wp_pin, spi_pin_drv[3], chip_id,
  min_chip_rev, min_chip_rev_full, max_chip_rev_full, reserved[4], hash_appended).
* Segments: ``<II`` (load_addr, data_len) then data.
* Padding so the 1-byte XOR checksum (seed 0xEF, over segment data only) is the
  last byte of a 16-byte block (relative to image start).
* If hash_appended == 1: 32-byte SHA-256 of image[0 : checksum_offset+1] follows.
* ``esp_app_desc_t`` (256 bytes, magic 0xABCD5432) starts the DROM segment's data;
  esptool takes the first DROM segment. We take the first segment whose data
  starts with the magic, which is chip-independent and equivalent for IDF images.
* Secure Boot V2 signature sector: at the next 4 KB boundary after the image
  (relative to image start), up to 3 blocks of 1216 bytes, each starting with
  0xE7 and version 0x02 (RSA-PSS) or 0x03 (ECDSA) (esptool ``espsecure``).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from flashtrace.io import CHIP_IDS, IMAGE_MAGIC
from flashtrace.model import Anomaly, ByteSource

HEADER_LEN = 8
EXT_HEADER_LEN = 16
SEG_HEADER_LEN = 8
MAX_SEGMENTS = 16
CHECKSUM_SEED = 0xEF
DIGEST_LEN = 32
APP_DESC_MAGIC = 0xABCD5432
APP_DESC_LEN = 256
SIG_SECTOR = 4096
SIG_BLOCK_LEN = 1216
SIG_BLOCK_MAGIC = 0xE7
SIG_BLOCK_VERSIONS = {0x02: "RSA", 0x03: "ECDSA"}
SIG_BLOCK_MAX = 3


@dataclass(frozen=True)
class ImageHeader:
    segment_count: int
    spi_mode: int
    spi_speed: int
    spi_size: int
    entry_addr: int
    wp_pin: int
    spi_pin_drv: bytes
    chip_id: int
    min_chip_rev: int
    min_chip_rev_full: int
    max_chip_rev_full: int
    hash_appended: int

    @property
    def chip(self) -> str | None:
        return CHIP_IDS.get(self.chip_id)


@dataclass(frozen=True)
class Segment:
    index: int
    header_offset: int  # absolute
    data_offset: int  # absolute
    load_addr: int
    data_len: int


@dataclass(frozen=True)
class AppDesc:
    offset: int  # absolute
    secure_version: int
    version: str
    project_name: str
    time: str
    date: str
    idf_ver: str
    app_elf_sha256: str
    min_efuse_blk_rev_full: int
    max_efuse_blk_rev_full: int
    mmu_page_size: int  # log2 of page size; 0 = not recorded
    hidden_string_bytes: tuple[str, ...]  # fields with non-NUL bytes after the terminator


@dataclass(frozen=True)
class SignatureBlock:
    offset: int  # absolute
    version: int

    @property
    def scheme(self) -> str:
        return SIG_BLOCK_VERSIONS.get(self.version, "unknown")


@dataclass(frozen=True)
class AppImage:
    offset: int  # absolute offset of image start
    header: ImageHeader | None
    segments: tuple[Segment, ...] = ()
    checksum_offset: int | None = None  # absolute
    checksum_stored: int | None = None
    checksum_computed: int | None = None
    sha256_offset: int | None = None  # absolute offset of the stored digest
    sha256_stored: str | None = None
    sha256_computed: str | None = None
    image_length: int | None = None  # incl. checksum and appended digest
    app_desc: AppDesc | None = None
    app_desc_segment: int | None = None
    signature_blocks: tuple[SignatureBlock, ...] = ()
    anomalies: tuple[Anomaly, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        return self.image_length is not None

    @property
    def checksum_valid(self) -> bool | None:
        if self.checksum_stored is None or self.checksum_computed is None:
            return None
        return self.checksum_stored == self.checksum_computed

    @property
    def sha256_valid(self) -> bool | None:
        if self.sha256_stored is None or self.sha256_computed is None:
            return None
        return self.sha256_stored == self.sha256_computed


def xor_checksum(chunks: list[memoryview], seed: int = CHECKSUM_SEED) -> int:
    acc = seed
    for chunk in chunks:
        # XOR-fold 8 bytes at a time, then the tail; equivalent to a byte-wise XOR.
        n8 = len(chunk) // 8
        if n8:
            words = memoryview(bytes(chunk[: n8 * 8])).cast("Q")
            w = 0
            for x in words:
                w ^= x
            for _ in range(8):
                acc ^= w & 0xFF
                w >>= 8
        for b in chunk[n8 * 8 :]:
            acc ^= b
    return acc


def _cstr(raw: bytes) -> tuple[str, bool]:
    """Decode a NUL-terminated fixed field; flag non-NUL bytes after the terminator."""
    head, sep, tail = raw.partition(b"\x00")
    hidden = bool(sep) and any(tail)
    return head.decode("utf-8", errors="backslashreplace"), hidden


def parse_app_desc(data: ByteSource, base_offset: int = 0) -> AppDesc | None:
    mv = memoryview(data)
    if len(mv) < APP_DESC_LEN:
        return None
    (magic,) = struct.unpack_from("<I", mv, 0)
    if magic != APP_DESC_MAGIC:
        return None
    (
        _magic,
        secure_version,
        _reserv1,
        version,
        project_name,
        time,
        date,
        idf_ver,
        elf_sha,
        min_efuse,
        max_efuse,
        mmu_page_size,
        _reserv3,
        _reserv2,
    ) = struct.unpack_from("<II8s32s32s16s16s32s32sHHB3s72s", mv, 0)
    hidden: list[str] = []
    decoded: dict[str, str] = {}
    for name, raw in (
        ("version", version),
        ("project_name", project_name),
        ("time", time),
        ("date", date),
        ("idf_ver", idf_ver),
    ):
        decoded[name], h = _cstr(raw)
        if h:
            hidden.append(name)
    return AppDesc(
        offset=base_offset,
        secure_version=secure_version,
        version=decoded["version"],
        project_name=decoded["project_name"],
        time=decoded["time"],
        date=decoded["date"],
        idf_ver=decoded["idf_ver"],
        app_elf_sha256=elf_sha.hex(),
        min_efuse_blk_rev_full=min_efuse,
        max_efuse_blk_rev_full=max_efuse,
        mmu_page_size=mmu_page_size,
        hidden_string_bytes=tuple(hidden),
    )


def parse_app_image(data: ByteSource, base_offset: int = 0) -> AppImage | None:
    """Parse an image starting at ``data[0]``; ``base_offset`` is its absolute dump offset.

    Returns ``None`` when ``data`` does not start with the image magic (e.g.
    an erased slot). Never raises on malformed input.
    """
    mv = memoryview(data)
    if len(mv) < 1 or mv[0] != IMAGE_MAGIC:
        return None
    anomalies: list[Anomaly] = []
    if len(mv) < HEADER_LEN + EXT_HEADER_LEN:
        anomalies.append(
            Anomaly(
                "IMG_TRUNCATED_HEADER",
                "image header truncated",
                base_offset,
                len(mv),
                {"available": len(mv)},
            )
        )
        return AppImage(offset=base_offset, header=None, anomalies=tuple(anomalies))

    _m, seg_count, spi_mode, speed_size, entry = struct.unpack_from("<BBBBI", mv, 0)
    wp_pin, d0, d1, d2, chip_id, min_rev, min_full, max_full, _res, hash_app = struct.unpack_from(
        "<BBBBHBHH4sB", mv, HEADER_LEN
    )
    header = ImageHeader(
        segment_count=seg_count,
        spi_mode=spi_mode,
        spi_speed=speed_size & 0x0F,
        spi_size=(speed_size >> 4) & 0x0F,
        entry_addr=entry,
        wp_pin=wp_pin,
        spi_pin_drv=bytes((d0, d1, d2)),
        chip_id=chip_id,
        min_chip_rev=min_rev,
        min_chip_rev_full=min_full,
        max_chip_rev_full=max_full,
        hash_appended=hash_app,
    )
    if seg_count > MAX_SEGMENTS:
        anomalies.append(
            Anomaly(
                "IMG_TOO_MANY_SEGMENTS",
                f"segment_count {seg_count} exceeds maximum {MAX_SEGMENTS}",
                base_offset + 1,
                1,
                {"segment_count": seg_count},
            )
        )
    if hash_app not in (0, 1):
        anomalies.append(
            Anomaly(
                "IMG_BAD_HASH_APPENDED",
                f"hash_appended byte is {hash_app:#04x} (expected 0 or 1)",
                base_offset + HEADER_LEN + EXT_HEADER_LEN - 1,
                1,
                {"value": hash_app},
            )
        )
    if header.chip is None:
        anomalies.append(
            Anomaly(
                "IMG_UNKNOWN_CHIP_ID",
                f"unknown chip_id {chip_id:#06x}",
                base_offset + 12,
                2,
                {"chip_id": chip_id},
            )
        )

    segments: list[Segment] = []
    seg_data: list[memoryview] = []
    pos = HEADER_LEN + EXT_HEADER_LEN
    truncated = False
    for i in range(seg_count):
        if pos + SEG_HEADER_LEN > len(mv):
            truncated = True
            anomalies.append(
                Anomaly(
                    "IMG_TRUNCATED_SEGMENT_HEADER",
                    f"segment {i} header truncated",
                    base_offset + pos,
                    len(mv) - pos,
                    {"segment": i},
                )
            )
            break
        load_addr, data_len = struct.unpack_from("<II", mv, pos)
        data_start = pos + SEG_HEADER_LEN
        if data_len > len(mv) - data_start:
            truncated = True
            anomalies.append(
                Anomaly(
                    "IMG_TRUNCATED_SEGMENT",
                    f"segment {i} declares {data_len} bytes but only {len(mv) - data_start} remain",
                    base_offset + pos,
                    len(mv) - pos,
                    {"segment": i, "declared": data_len, "available": len(mv) - data_start},
                )
            )
            break
        segments.append(
            Segment(i, base_offset + pos, base_offset + data_start, load_addr, data_len)
        )
        seg_data.append(mv[data_start : data_start + data_len])
        pos = data_start + data_len

    app_desc: AppDesc | None = None
    app_desc_segment: int | None = None
    for seg, chunk in zip(segments, seg_data, strict=True):
        app_desc = parse_app_desc(chunk, seg.data_offset)
        if app_desc is not None:
            app_desc_segment = seg.index
            break
    if app_desc is not None and app_desc.hidden_string_bytes:
        anomalies.append(
            Anomaly(
                "IMG_APP_DESC_HIDDEN_BYTES",
                "esp_app_desc_t string field(s) carry bytes after the NUL terminator",
                app_desc.offset,
                APP_DESC_LEN,
                {"fields": list(app_desc.hidden_string_bytes)},
            )
        )

    if truncated:
        return AppImage(
            offset=base_offset,
            header=header,
            segments=tuple(segments),
            app_desc=app_desc,
            app_desc_segment=app_desc_segment,
            anomalies=tuple(anomalies),
        )

    checksum_pos = pos + (15 - pos % 16)
    computed = xor_checksum(seg_data)
    if checksum_pos >= len(mv):
        anomalies.append(
            Anomaly(
                "IMG_TRUNCATED_CHECKSUM",
                "image ends before its checksum byte",
                base_offset + pos,
                len(mv) - pos,
            )
        )
        return AppImage(
            offset=base_offset,
            header=header,
            segments=tuple(segments),
            checksum_computed=computed,
            app_desc=app_desc,
            app_desc_segment=app_desc_segment,
            anomalies=tuple(anomalies),
        )
    stored = mv[checksum_pos]
    if stored != computed:
        anomalies.append(
            Anomaly(
                "IMG_CHECKSUM_BAD",
                f"image checksum {stored:#04x} != computed {computed:#04x}",
                base_offset + checksum_pos,
                1,
                {"stored": stored, "computed": computed},
            )
        )
    end = checksum_pos + 1
    sha_offset: int | None = None
    sha_stored: str | None = None
    sha_computed: str | None = None
    if hash_app == 1:
        sha_computed = hashlib.sha256(mv[:end]).hexdigest()
        if end + DIGEST_LEN > len(mv):
            anomalies.append(
                Anomaly(
                    "IMG_TRUNCATED_DIGEST",
                    "image ends before its appended SHA-256",
                    base_offset + end,
                    len(mv) - end,
                )
            )
            return AppImage(
                offset=base_offset,
                header=header,
                segments=tuple(segments),
                checksum_offset=base_offset + checksum_pos,
                checksum_stored=stored,
                checksum_computed=computed,
                sha256_computed=sha_computed,
                app_desc=app_desc,
                app_desc_segment=app_desc_segment,
                anomalies=tuple(anomalies),
            )
        sha_offset = base_offset + end
        sha_stored = bytes(mv[end : end + DIGEST_LEN]).hex()
        if sha_stored != sha_computed:
            anomalies.append(
                Anomaly(
                    "IMG_SHA256_BAD",
                    "appended SHA-256 does not match image contents",
                    sha_offset,
                    DIGEST_LEN,
                    {"stored": sha_stored, "computed": sha_computed},
                )
            )
        end += DIGEST_LEN

    return AppImage(
        offset=base_offset,
        header=header,
        segments=tuple(segments),
        checksum_offset=base_offset + checksum_pos,
        checksum_stored=stored,
        checksum_computed=computed,
        sha256_offset=sha_offset,
        sha256_stored=sha_stored,
        sha256_computed=sha_computed,
        image_length=end,
        app_desc=app_desc,
        app_desc_segment=app_desc_segment,
        signature_blocks=find_signature_blocks(mv, end, base_offset),
        anomalies=tuple(anomalies),
    )


def find_signature_blocks(
    data: ByteSource, image_length: int, base_offset: int = 0
) -> tuple[SignatureBlock, ...]:
    """Structural scan for Secure Boot V2 signature blocks after an image.

    Presence only: signatures are not verified.
    """
    mv = memoryview(data)
    sector = -(-image_length // SIG_SECTOR) * SIG_SECTOR if image_length > 0 else 0
    blocks: list[SignatureBlock] = []
    for i in range(SIG_BLOCK_MAX):
        off = sector + i * SIG_BLOCK_LEN
        if off + SIG_BLOCK_LEN > len(mv):
            break
        if mv[off] != SIG_BLOCK_MAGIC or mv[off + 1] not in SIG_BLOCK_VERSIONS:
            break
        blocks.append(SignatureBlock(base_offset + off, mv[off + 1]))
    return tuple(blocks)
