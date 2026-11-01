"""SPIFFS image writer mirroring ESP-IDF v5.3.1 ``components/spiffs/spiffsgen.py``.

Default ESP-IDF configuration only: page 256, block 4096, obj_name_len 32,
meta_len 4, 2-byte object/span/page/block indices, little-endian, use_magic and
use_magic_len enabled, aligned_obj_ix_tables disabled. ``tests/test_spiffs.py``
asserts byte identity with spiffsgen.py in CI.

Files are written in the order given (spiffsgen uses ``os.walk`` order).
"""

from __future__ import annotations

import math
import struct

PAGE = 256
BLOCK = 4096
NAME_LEN = 32
META_LEN = 4
OBJ_ID_LEN = SPAN_IX_LEN = PAGE_IX_LEN = 2
FLAG_USED_FINAL_INDEX = 0xF8
FLAG_USED_FINAL = 0xFC
TYPE_FILE = 1

PAGES_PER_BLOCK = BLOCK // PAGE
LU_PAGES = math.ceil(BLOCK / PAGE * OBJ_ID_LEN / PAGE)
USABLE_PAGES = PAGES_PER_BLOCK - LU_PAGES
LU_IDS_LIM = PAGE // OBJ_ID_LEN
DATA_HDR = OBJ_ID_LEN + SPAN_IX_LEN + 1
DATA_HDR_ALIGNED = DATA_HDR + (4 - (4 if DATA_HDR % 4 == 0 else DATA_HDR % 4))
DATA_CONTENT = PAGE - DATA_HDR
IX_HDR = DATA_HDR_ALIGNED + 4 + 1 + NAME_LEN + META_LEN
IX_HEAD_LIM = (PAGE - IX_HDR) // PAGE_IX_LEN
IX_LIM = (PAGE - DATA_HDR_ALIGNED) // PAGE_IX_LEN
MSB = 1 << (OBJ_ID_LEN * 8 - 1)


class SpiffsFullError(RuntimeError):
    pass


def lu_magic(bix: int, blocks_lim: int) -> int:
    magic = (0x20140529 ^ PAGE) ^ (blocks_lim - bix)
    return magic & ((2 << (8 * OBJ_ID_LEN)) - 1)


class _IndexPage:
    def __init__(self, obj_id: int, span_ix: int, size: int, name: str) -> None:
        self.obj_id, self.span_ix, self.size, self.name = obj_id, span_ix, size, name
        self.lim = IX_HEAD_LIM if span_ix == 0 else IX_LIM
        self.pages: list[int] = []

    def register(self, offset: int) -> None:
        if self.lim <= 0:
            raise SpiffsFullError
        self.pages.append(offset)
        self.lim -= 1

    def to_bytes(self) -> bytes:
        img = struct.pack("<HHB", self.obj_id ^ MSB, self.span_ix, FLAG_USED_FINAL_INDEX)
        img += b"\xff" * (DATA_HDR_ALIGNED - DATA_HDR)
        if self.span_ix == 0:
            img += struct.pack("<IB", self.size, TYPE_FILE)
            img += self.name.encode() + b"\x00" * (NAME_LEN - len(self.name) + META_LEN)
        for off in self.pages:
            img += struct.pack("<H", off >> int(math.log(PAGE, 2)))
        return img + b"\xff" * (PAGE - len(img))


class _DataPage:
    def __init__(self, offset: int, obj_id: int, span_ix: int, contents: bytes) -> None:
        self.offset, self.obj_id, self.span_ix, self.contents = offset, obj_id, span_ix, contents

    def to_bytes(self) -> bytes:
        img = struct.pack("<HHB", self.obj_id, self.span_ix, FLAG_USED_FINAL) + self.contents
        return img + b"\xff" * (PAGE - len(img))


class _LuPage:
    def __init__(self, bix: int) -> None:
        self.bix = bix
        self.ids: list[tuple[int, bool]] = []  # (obj_id, is_index)
        self.lim = LU_IDS_LIM

    def register(self, obj_id: int, is_index: bool) -> None:
        if self.lim <= 0:
            raise SpiffsFullError
        self.ids.append((obj_id, is_index))
        self.lim -= 1

    def magicfy(self, blocks_lim: int) -> None:
        remaining = self.lim
        if remaining >= 2:
            for i in range(remaining):
                if i == remaining - 2:
                    self.ids.append((lu_magic(self.bix, blocks_lim), False))
                    break
                self.ids.append((0xFFFF, False))
                self.lim -= 1

    def to_bytes(self) -> bytes:
        img = b"".join(struct.pack("<H", oid ^ MSB if ix else oid) for oid, ix in self.ids)
        return img + b"\xff" * (PAGE - len(img))


class _Block:
    def __init__(self, bix: int) -> None:
        self.bix = bix
        self.offset = bix * BLOCK
        self.remaining = USABLE_PAGES
        self.lu = _LuPage(bix)
        self.pages: list[_LuPage | _IndexPage | _DataPage] = [self.lu]
        self.reset()

    def reset(self) -> None:
        self.cur_ix_span = 0
        self.cur_data_span = 0
        self.cur_obj_id = 0
        self.cur_ix: _IndexPage | None = None

    def _register(self, page: _IndexPage | _DataPage) -> None:
        if isinstance(page, _DataPage):
            assert self.cur_ix is not None
            self.cur_ix.register(page.offset)
        self.lu.register(page.obj_id, isinstance(page, _IndexPage))
        self.pages.append(page)

    def begin_obj(
        self, obj_id: int, size: int, name: str, ix_span: int = 0, data_span: int = 0
    ) -> None:
        if self.remaining <= 0:
            raise SpiffsFullError
        self.reset()
        self.cur_obj_id, self.cur_ix_span, self.cur_data_span = obj_id, ix_span, data_span
        page = _IndexPage(obj_id, self.cur_ix_span, size, name)
        self._register(page)
        self.cur_ix = page
        self.remaining -= 1
        self.cur_ix_span += 1

    def update_obj(self, contents: bytes) -> None:
        if self.remaining <= 0:
            raise SpiffsFullError
        page = _DataPage(
            self.offset + len(self.pages) * PAGE, self.cur_obj_id, self.cur_data_span, contents
        )
        self._register(page)
        self.cur_data_span += 1
        self.remaining -= 1

    def is_full(self) -> bool:
        return self.remaining <= 0

    def to_bytes(self, blocks_lim: int) -> bytes:
        img = b""
        for idx, page in enumerate(self.pages):
            if idx == LU_PAGES - 1:
                assert isinstance(page, _LuPage)
                page.magicfy(blocks_lim)
            img += page.to_bytes()
        return img + b"\xff" * (BLOCK - len(img))


def build_spiffs(files: list[tuple[str, bytes]], size: int) -> bytes:
    """Build an image; ``files`` = [(path starting with '/', contents), ...]."""
    if size % BLOCK:
        raise ValueError("image size should be a multiple of block size")
    blocks: list[_Block] = []
    blocks_lim = size // BLOCK
    obj_id = 1

    def new_block() -> _Block:
        if len(blocks) >= blocks_lim:
            raise SpiffsFullError("the image size has been exceeded")
        b = _Block(len(blocks))
        blocks.append(b)
        return b

    for name, contents in files:
        if len(name) > NAME_LEN:
            raise ValueError(f"object name {name!r} too long")
        try:
            block = blocks[-1]
            block.begin_obj(obj_id, len(contents), name)
        except (IndexError, SpiffsFullError):
            block = new_block()
            block.begin_obj(obj_id, len(contents), name)
        pos = 0
        chunk = contents[pos : pos + DATA_CONTENT]
        while chunk:
            try:
                block = blocks[-1]
                try:
                    block.update_obj(chunk)
                except SpiffsFullError:
                    if block.is_full():
                        raise
                    block.begin_obj(
                        obj_id, len(contents), name, block.cur_ix_span, block.cur_data_span
                    )
                    continue
            except (IndexError, SpiffsFullError):
                prev = block
                block = new_block()
                block.cur_obj_id = prev.cur_obj_id
                block.cur_ix = prev.cur_ix
                block.cur_data_span = prev.cur_data_span
                block.cur_ix_span = prev.cur_ix_span
                continue
            pos += DATA_CONTENT
            chunk = contents[pos : pos + DATA_CONTENT]
        block.reset()
        obj_id += 1

    out = [b.to_bytes(blocks_lim) for b in blocks]
    bix = len(blocks)
    while bix < blocks_lim:
        out.append(_Block(bix).to_bytes(blocks_lim))
        bix += 1
    return b"".join(out)
