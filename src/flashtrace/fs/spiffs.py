"""Read-only SPIFFS parser for the ESP-IDF default configuration.

Layout from ESP-IDF v5.3.1 ``components/spiffs/spiffsgen.py`` (see
``tools/corpus/spiffs_writer.py``): page 256 B, block 4096 B, one object-lookup
page per block holding a u16 object id per page (MSB set = index page,
0xFFFF = free) and a per-block magic at lookup slot ``page/2 - 2`` equal to
``(0x20140529 ^ page_size ^ (blocks - bix)) & 0x1FFFF`` (truncated to u16).
Data page header: obj_id u16, span_ix u16, flags u8 (0xFC = used+final), then
251 content bytes. Index page header (span 0): obj_id|0x8000 u16, span_ix u16,
flags u8 (0xF8), 3 pad bytes, size u32, type u8, name[32], meta[4], then u16
page indices.

ASSUMPTION (not verifiable from spiffsgen, which only writes fresh images): pages
whose flags have bit 7 (DELET) cleared, or whose lookup id is 0x0000, are deleted;
they are counted but not reassembled.
"""

from __future__ import annotations

import struct

from flashtrace.fs import MAX_FILES, MAX_TOTAL_BYTES, FsFile, FsListing
from flashtrace.model import Anomaly, ByteSource, Segment

PAGE = 256
BLOCK = 4096
PAGES_PER_BLOCK = BLOCK // PAGE
LU_PAGES = 1
DATA_HDR = 5
DATA_CONTENT = PAGE - DATA_HDR
IX_HDR_ALIGNED = 8
NAME_LEN = 32
MSB = 0x8000
FLAG_DELETED_BIT = 0x80
FLAG_INDEX_BIT = 0x04  # cleared on index pages (0xF8)


def lu_magic(bix: int, blocks: int) -> int:
    return ((0x20140529 ^ PAGE) ^ (blocks - bix)) & 0x1FFFF & 0xFFFF


def looks_like_spiffs(data: ByteSource) -> bool:
    mv = memoryview(data)
    blocks = len(mv) // BLOCK
    if blocks == 0:
        return False
    slot = PAGE // 2 - 2
    hits = 0
    for bix in range(min(blocks, 8)):
        (val,) = struct.unpack_from("<H", mv, bix * BLOCK + slot * 2)
        hits += val == lu_magic(bix, blocks)
    return hits > 0


def parse_spiffs(data: ByteSource, base_offset: int = 0, partition: str | None = None) -> FsListing:
    mv = memoryview(data)
    blocks = len(mv) // BLOCK
    anomalies: list[Anomaly] = []
    if not looks_like_spiffs(mv):
        return FsListing(
            "spiffs",
            partition,
            base_offset,
            len(mv),
            False,
            "no SPIFFS lookup-page magic found (page 256 / block 4096 assumed)",
            anomalies=(
                Anomaly(
                    "FS_SPIFFS_UNRECOGNISED",
                    "partition could not be parsed as SPIFFS with ESP-IDF defaults",
                    base_offset,
                    len(mv),
                    {"partition": partition},
                ),
            ),
        )
    # obj_id -> (name, size, index page offset)
    heads: dict[int, tuple[str, int, int]] = {}
    data_pages: dict[int, dict[int, int]] = {}  # obj_id -> span_ix -> page offset
    deleted = 0
    for bix in range(blocks):
        boff = bix * BLOCK
        for p in range(LU_PAGES, PAGES_PER_BLOCK):
            (lu_id,) = struct.unpack_from("<H", mv, boff + (p - LU_PAGES) * 2)
            if lu_id == 0xFFFF:
                continue
            poff = boff + p * PAGE
            obj_id, span_ix, flags = struct.unpack_from("<HHB", mv, poff)
            if lu_id == 0 or not flags & FLAG_DELETED_BIT:
                deleted += 1
                continue
            if obj_id & MSB and not flags & FLAG_INDEX_BIT:
                if span_ix != 0:
                    continue
                size, _typ = struct.unpack_from("<IB", mv, poff + IX_HDR_ALIGNED)
                raw_name = bytes(
                    mv[poff + IX_HDR_ALIGNED + 5 : poff + IX_HDR_ALIGNED + 5 + NAME_LEN]
                )
                name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="backslashreplace")
                heads[obj_id & ~MSB] = (name, size, poff)
            elif not obj_id & MSB:
                data_pages.setdefault(obj_id, {})[span_ix] = poff
    files: list[FsFile] = []
    total = 0
    for obj_id, (name, size, _ix_off) in sorted(heads.items()):
        if len(files) >= MAX_FILES or total >= MAX_TOTAL_BYTES:
            anomalies.append(Anomaly("FS_TOO_MANY_FILES", "file listing truncated", base_offset, 0))
            break
        spans = data_pages.get(obj_id, {})
        need = -(-size // DATA_CONTENT) if size else 0
        parts: list[bytes] = []
        segs: list[Segment] = []
        complete = True
        rel = 0
        for s in range(need):
            page_off = spans.get(s)
            if page_off is None:
                complete = False
                break
            take = min(DATA_CONTENT, size - rel)
            parts.append(bytes(mv[page_off + DATA_HDR : page_off + DATA_HDR + take]))
            segs.append(Segment(rel, base_offset + page_off + DATA_HDR, take))
            rel += take
        content = b"".join(parts)
        total += len(content)
        if not complete:
            anomalies.append(
                Anomaly(
                    "FS_SPIFFS_INCOMPLETE",
                    f"SPIFFS file {name!r} is missing data pages",
                    base_offset,
                    0,
                    {"path": name, "size": size, "recovered": len(content)},
                )
            )
        files.append(FsFile(name, size, content, tuple(segs), complete, complete))
    detail = f"page=256 block=4096 blocks={blocks} deleted_pages={deleted}"
    return FsListing(
        "spiffs", partition, base_offset, len(mv), True, detail, tuple(files), (), tuple(anomalies)
    )
