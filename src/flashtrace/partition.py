"""ESP-IDF partition table parser.

Format confirmed against ESP-IDF v5.3.1 ``components/partition_table/gen_esp32part.py``:

* 32-byte entries, ``struct '<2sBBLL16sL'``: magic ``AA 50``, type, subtype,
  offset, size, label[16] (NUL-padded), flags (bit0 encrypted, bit1 readonly).
* Optional MD5 entry: ``EB EB`` + 14 x ``FF`` + MD5 (16 bytes) of all preceding
  entry bytes.
* Table ends at an all-``FF`` entry. Max table length 0xC00 bytes.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from flashtrace.model import Anomaly, ByteSource

ENTRY_SIZE = 32
ENTRY_MAGIC = b"\xaa\x50"
MD5_MAGIC = b"\xeb\xeb"
MAX_TABLE_LENGTH = 0xC00
DEFAULT_TABLE_OFFSET = 0x8000
SECTOR = 0x1000

TYPE_APP = 0x00
TYPE_DATA = 0x01

APP_SUBTYPES: dict[int, str] = {0x00: "factory", 0x20: "test"} | {
    0x10 + i: f"ota_{i}" for i in range(16)
}
DATA_SUBTYPES: dict[int, str] = {
    0x00: "ota",
    0x01: "phy",
    0x02: "nvs",
    0x03: "coredump",
    0x04: "nvs_keys",
    0x05: "efuse",
    0x06: "undefined",
    0x80: "esphttpd",
    0x81: "fat",
    0x82: "spiffs",
    0x83: "littlefs",
}

FLAG_ENCRYPTED = 1 << 0
FLAG_READONLY = 1 << 1


@dataclass(frozen=True)
class PartitionEntry:
    index: int
    entry_offset: int  # absolute offset of this 32-byte entry in the dump
    type: int
    subtype: int
    offset: int
    size: int
    label: str
    flags: int

    @property
    def type_name(self) -> str:
        return {TYPE_APP: "app", TYPE_DATA: "data"}.get(self.type, f"{self.type:#04x}")

    @property
    def subtype_name(self) -> str:
        table = {TYPE_APP: APP_SUBTYPES, TYPE_DATA: DATA_SUBTYPES}.get(self.type, {})
        return table.get(self.subtype, f"{self.subtype:#04x}")

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def readonly(self) -> bool:
        return bool(self.flags & FLAG_READONLY)

    @property
    def is_ota_app(self) -> bool:
        return self.type == TYPE_APP and 0x10 <= self.subtype <= 0x1F

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class PartitionTable:
    offset: int  # absolute offset of the table in the dump
    entries: tuple[PartitionEntry, ...]
    length: int  # bytes consumed, including MD5 entry and end marker if present
    md5_present: bool
    md5_stored: str | None
    md5_computed: str | None
    md5_entry_offset: int | None
    end_marker_found: bool
    anomalies: tuple[Anomaly, ...]

    @property
    def md5_valid(self) -> bool | None:
        if not self.md5_present:
            return None
        return self.md5_stored == self.md5_computed

    def by_label(self, label: str) -> PartitionEntry | None:
        return next((e for e in self.entries if e.label == label), None)

    def find(self, type_: int, subtype: int | None = None) -> list[PartitionEntry]:
        return [
            e for e in self.entries if e.type == type_ and (subtype is None or e.subtype == subtype)
        ]

    @property
    def ota_apps(self) -> list[PartitionEntry]:
        return sorted((e for e in self.entries if e.is_ota_app), key=lambda e: e.subtype)


def _decode_label(raw: bytes) -> str:
    raw = raw.split(b"\x00", 1)[0]
    return raw.decode("utf-8", errors="backslashreplace")


def parse_partition_table(data: ByteSource, base_offset: int = 0) -> PartitionTable:
    """Parse a partition table from ``data`` (which starts at the table).

    ``base_offset`` is the absolute dump offset of ``data[0]``. Never raises on
    malformed input; problems are returned as anomalies.
    """
    mv = memoryview(data)[:MAX_TABLE_LENGTH]
    entries: list[PartitionEntry] = []
    anomalies: list[Anomaly] = []
    md5 = hashlib.md5()  # noqa: S324 - format-defined integrity check, not security
    md5_present = False
    md5_stored: str | None = None
    md5_computed: str | None = None
    md5_entry_offset: int | None = None
    end_found = False
    pos = 0
    while pos + ENTRY_SIZE <= len(mv):
        raw = bytes(mv[pos : pos + ENTRY_SIZE])
        abs_off = base_offset + pos
        if raw == b"\xff" * ENTRY_SIZE:
            end_found = True
            pos += ENTRY_SIZE
            break
        if raw[:2] == MD5_MAGIC:
            md5_present = True
            md5_entry_offset = abs_off
            md5_stored = raw[16:].hex()
            md5_computed = md5.hexdigest()
            if raw[2:16] != b"\xff" * 14:
                anomalies.append(
                    Anomaly(
                        "PT_MD5_ENTRY_PADDING",
                        "MD5 entry padding is not 14 x 0xFF",
                        abs_off,
                        16,
                    )
                )
            pos += ENTRY_SIZE
            continue
        if raw[:2] != ENTRY_MAGIC:
            anomalies.append(
                Anomaly(
                    "PT_BAD_ENTRY_MAGIC",
                    f"partition entry {len(entries)} has bad magic {raw[:2].hex()}",
                    abs_off,
                    ENTRY_SIZE,
                    {"magic": raw[:2].hex()},
                )
            )
            break
        if md5_present:
            anomalies.append(
                Anomaly(
                    "PT_ENTRY_AFTER_MD5",
                    "partition entry follows the MD5 entry",
                    abs_off,
                    ENTRY_SIZE,
                )
            )
        md5.update(raw)
        _, ptype, subtype, poff, psize, label, flags = struct.unpack("<2sBBLL16sL", raw)
        entries.append(
            PartitionEntry(
                index=len(entries),
                entry_offset=abs_off,
                type=ptype,
                subtype=subtype,
                offset=poff,
                size=psize,
                label=_decode_label(label),
                flags=flags,
            )
        )
        pos += ENTRY_SIZE
    else:
        if not end_found:
            anomalies.append(
                Anomaly(
                    "PT_NO_END_MARKER",
                    "partition table has no end-of-table marker",
                    base_offset + pos,
                    0,
                )
            )
    if md5_present and md5_stored != md5_computed and md5_entry_offset is not None:
        anomalies.append(
            Anomaly(
                "PT_MD5_MISMATCH",
                "partition table MD5 does not match its entries",
                md5_entry_offset,
                ENTRY_SIZE,
                {"stored": md5_stored, "computed": md5_computed},
            )
        )
    return PartitionTable(
        offset=base_offset,
        entries=tuple(entries),
        length=pos,
        md5_present=md5_present,
        md5_stored=md5_stored,
        md5_computed=md5_computed,
        md5_entry_offset=md5_entry_offset,
        end_marker_found=end_found,
        anomalies=tuple(anomalies),
    )


def looks_like_table(dump: ByteSource, offset: int) -> bool:
    mv = memoryview(dump)
    if offset < 0 or offset + ENTRY_SIZE > len(mv):
        return False
    return bytes(mv[offset : offset + 2]) == ENTRY_MAGIC


def plausible_table(dump: ByteSource, offset: int) -> bool:
    """Stricter check used when *scanning* for a relocated table.

    Two magic bytes alone match random/encrypted data at ~1 in 65536 offsets, so a
    scanned candidate must also parse as a sane table: >= 1 entry, printable labels,
    4 KB-aligned non-empty partitions, and an end marker or a valid MD5 entry.
    """
    if not looks_like_table(dump, offset):
        return False
    mv = memoryview(dump)
    t = parse_partition_table(mv[offset : offset + MAX_TABLE_LENGTH], offset)
    if not t.entries or not (t.end_marker_found or t.md5_valid):
        return False
    for e in t.entries:
        if not e.label or not e.label.isprintable() or not e.label.isascii():
            return False
        if e.offset % SECTOR or e.size == 0:
            return False
    return True


def find_partition_table(
    dump: ByteSource, default_offset: int = DEFAULT_TABLE_OFFSET
) -> int | None:
    """Return the table offset: ``default_offset`` if its magic is there, else the first
    4 KB-aligned offset holding a :func:`plausible_table`."""
    if looks_like_table(dump, default_offset):
        return default_offset
    for off in range(0, len(dump) - ENTRY_SIZE + 1, SECTOR):
        if plausible_table(dump, off):
            return off
    return None


def layout_anomalies(table: PartitionTable, dump_size: int) -> tuple[Anomaly, ...]:
    """Structural layout problems: overlapping and out-of-bounds partitions."""
    out: list[Anomaly] = []
    for e in table.entries:
        if e.end > dump_size:
            out.append(
                Anomaly(
                    "PT_OUT_OF_BOUNDS",
                    f"partition {e.label!r} [{e.offset:#x}, {e.end:#x}) exceeds dump size"
                    f" {dump_size:#x}",
                    e.entry_offset,
                    ENTRY_SIZE,
                    {"label": e.label, "offset": e.offset, "size": e.size, "dump_size": dump_size},
                )
            )
    ordered = sorted(table.entries, key=lambda e: (e.offset, e.index))
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            if b.offset >= a.end:
                break
            if a.size and b.size:
                out.append(
                    Anomaly(
                        "PT_OVERLAP",
                        f"partitions {a.label!r} and {b.label!r} overlap",
                        min(a.entry_offset, b.entry_offset),
                        abs(a.entry_offset - b.entry_offset) + ENTRY_SIZE,
                        {"a": a.label, "b": b.label},
                    )
                )
    return tuple(out)


def partition_slice(dump: ByteSource, entry: PartitionEntry) -> memoryview:
    """Bounds-clamped view of a partition's bytes."""
    mv = memoryview(dump)
    start = min(entry.offset, len(mv))
    end = min(entry.offset + entry.size, len(mv))
    return mv[start:end]
