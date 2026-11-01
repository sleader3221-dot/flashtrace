"""NVS partition writer that mirrors esp-idf-nvs-partition-gen 0.2.0 byte for byte.

Ported from ``esp_idf_nvs_partition_gen/nvs_partition_gen.py`` @ v0.2.0 (commit
421a821), version-2 (multipage blob) format, unencrypted. Quirks are kept
deliberately (e.g. a non-blob entry never uses a page's last slot, blob chunks
store unrounded data but occupy rounded slots, the automatic ``sta.*`` Wi-Fi
extras). ``tests/test_nvs_official.py`` asserts byte identity with the official
tool in CI, which is what makes this writer trustworthy for the corpus.

Only CSV row types ``namespace`` and ``data`` are supported.
"""

from __future__ import annotations

import binascii
import re
import struct
import zlib
from dataclasses import dataclass, field

from flashtrace.nvs import NvsPartition

PAGE_SIZE = 4096
ENTRY_SIZE = 32
MAX_ENTRIES = 126
FIRST_ENTRY_OFFSET = 64
ACTIVE = 0xFFFFFFFE
FULL = 0xFFFFFFFC
VERSION2 = 0xFE
CHUNK_ANY = 0xFF
MAX_BLOB_SIZE_V2 = 4000

TYPES = {
    "u8": (0x01, "<B"),
    "i8": (0x11, "<b"),
    "u16": (0x02, "<H"),
    "i16": (0x12, "<h"),
    "u32": (0x04, "<I"),
    "i32": (0x14, "<i"),
    "u64": (0x08, "<Q"),
    "i64": (0x18, "<q"),
}
SZ, BLOB, BLOB_DATA, BLOB_IDX = 0x21, 0x41, 0x42, 0x48


class PageFullError(RuntimeError):
    pass


class InsufficientSizeError(RuntimeError):
    pass


def _crc(data: bytes) -> int:
    return zlib.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF


def _set_header_crc(entry: bytearray) -> None:
    struct.pack_into("<I", entry, 4, _crc(bytes(entry[0:4]) + bytes(entry[8:32])))


@dataclass
class _Page:
    num: int
    buf: bytearray = field(default_factory=lambda: bytearray(b"\xff" * PAGE_SIZE))
    entry_num: int = 0
    bitmap: bytearray = field(default_factory=lambda: bytearray(b"\xff" * 32))

    def init_header(self) -> None:
        hdr = bytearray(b"\xff" * 32)
        struct.pack_into("<I", hdr, 0, ACTIVE)
        struct.pack_into("<I", hdr, 4, self.num)
        hdr[8] = VERSION2
        struct.pack_into("<I", hdr, 28, _crc(bytes(hdr[4:28])))
        self.buf[0:32] = hdr

    def write(self, data: bytes, entrycount: int) -> None:
        start = FIRST_ENTRY_OFFSET + ENTRY_SIZE * self.entry_num
        self.buf[start : start + len(data)] = data
        for _ in range(entrycount):
            bitnum = self.entry_num * 2
            self.bitmap[bitnum // 8] &= ~(1 << (bitnum & 7)) & 0xFF
            self.buf[32:64] = self.bitmap
            self.entry_num += 1


class NvsWriter:
    def __init__(self, size: int) -> None:
        if size % PAGE_SIZE or size < 3 * PAGE_SIZE:
            raise ValueError("size must be a multiple of 4096 and >= 0x3000")
        self.size_left = size - PAGE_SIZE  # one page reserved (check_size)
        self.total = size
        self.pages: list[_Page] = []
        self.page_num = -1
        self.ns_count = 0
        self.ns_idx = 0
        self.written_ns: dict[str, int] = {}
        self._wifi_extras = False
        self._new_page()

    # -- pages -------------------------------------------------------------
    def _new_page(self, *, empty: bool = False, reserved: bool = False) -> _Page:
        if self.pages and not empty:
            cur = self.pages[-1]
            if struct.unpack_from("<I", cur.buf, 0)[0] == ACTIVE:
                struct.pack_into("<I", cur.buf, 0, FULL)
        if self.size_left == 0:
            raise InsufficientSizeError("partition too small")
        if not reserved:
            self.size_left -= PAGE_SIZE
        self.page_num += 1
        page = _Page(self.page_num)
        if not empty:
            page.init_header()
        self.pages.append(page)
        return page

    @property
    def cur(self) -> _Page:
        return self.pages[-1]

    # -- primitive / varlen ------------------------------------------------
    def _primitive(self, page: _Page, key: str, value: int, enc: str, ns: int) -> None:
        if page.entry_num >= MAX_ENTRIES:
            raise PageFullError
        e = bytearray(b"\xff" * 32)
        e[0] = ns
        e[2] = 1
        e[3] = CHUNK_ANY
        e[8:24] = b"\x00" * 16
        e[8 : 8 + len(key)] = key.encode()
        code, fmt = TYPES[enc]
        e[1] = code
        struct.pack_into(fmt, e, 24, value)
        _set_header_crc(e)
        page.write(bytes(e), 1)

    def _single_page(self, page: _Page, e: bytearray, data: bytes, count: int) -> None:
        struct.pack_into("<H", e, 24, len(data))
        struct.pack_into("<I", e, 28, _crc(data))
        _set_header_crc(e)
        page.write(bytes(e), 1)
        page.write(data, count)

    def _blob_chunks(self, e: bytearray, data: bytes) -> None:
        page = self.cur
        offset = 0
        remaining = len(data)
        chunk_count = 0
        while True:
            tailroom = (MAX_ENTRIES - page.entry_num - 1) * ENTRY_SIZE
            assert tailroom >= 0, "Page overflow!!"
            chunk_size = tailroom if tailroom < remaining else remaining
            remaining -= chunk_size
            e[1] = BLOB_DATA
            rounded = (chunk_size + 31) & ~31
            e[2] = rounded // 32 + 1
            e[3] = chunk_count
            chunk = data[offset : offset + chunk_size]
            struct.pack_into("<H", e, 24, chunk_size)
            struct.pack_into("<I", e, 28, _crc(chunk))
            _set_header_crc(e)
            page.write(bytes(e), 1)
            page.write(chunk, rounded // 32)
            chunk_count += 1
            if remaining or (tailroom - chunk_size) < ENTRY_SIZE:
                page = self._new_page()
            offset += chunk_size
            if not remaining:
                e[24:32] = b"\xff" * 8
                e[1] = BLOB_IDX
                e[2] = 1
                e[3] = CHUNK_ANY
                struct.pack_into("<I", e, 24, len(data))
                e[28] = chunk_count
                e[29] = 0
                _set_header_crc(e)
                page.write(bytes(e), 1)
                return

    def _varlen(self, page: _Page, key: str, data: bytes, is_string: bool, ns: int) -> None:
        if is_string and len(data) > MAX_BLOB_SIZE_V2:
            raise ValueError(f"string too long for key {key}")
        count = ((len(data) + 31) & ~31) // 32
        if page.entry_num >= MAX_ENTRIES:
            raise PageFullError
        if page.entry_num + count + 1 >= MAX_ENTRIES and is_string:
            raise PageFullError
        e = bytearray(b"\xff" * 32)
        e[0] = ns
        if is_string:
            e[2] = count + 1
        e[3] = CHUNK_ANY
        e[8:24] = b"\x00" * 16
        e[8 : 8 + len(key)] = key.encode()
        e[1] = SZ if is_string else BLOB
        if is_string:
            self._single_page(page, e, data, count)
        else:
            self._blob_chunks(e, data)

    # -- public API (mirrors write_entry / NVS.write_entry) ----------------
    def namespace(self, name: str) -> None:
        idx = self.written_ns.get(name)
        if idx:
            self.ns_idx = idx
            return
        self.ns_count += 1
        self.ns_idx = self.ns_count
        try:
            self._primitive(self.cur, name, self.ns_idx, "u8", 0)
        except PageFullError:
            self._primitive(self._new_page(), name, self.ns_idx, "u8", 0)
        self.written_ns[name] = self.ns_idx

    def _entry(self, key: str, value: str | bytes, encoding: str) -> None:
        m = re.match(r"(blob_fill|blob_sz_fill)\((\d+);(0x[0-9a-fA-F]{2})\)", encoding)
        if m:
            pad, length = int(m.group(3), 16), int(m.group(2))
            vb = value.encode() if isinstance(value, str) else value
            if len(vb) > length:
                raise ValueError(f"{key}: value longer than {length}")
            body = vb + bytes([pad] * (length - len(vb)))
            data_bytes = struct.pack("<I", len(vb)) + body if m.group(1) == "blob_sz_fill" else body
            value, encoding = data_bytes.hex(), "hex2bin"
        ns = self.ns_count
        if encoding in TYPES:
            ival = int(value)
            try:
                self._primitive(self.cur, key, ival, encoding, ns)
            except PageFullError:
                self._primitive(self._new_page(), key, ival, encoding, ns)
            return
        if encoding == "string":
            data = (value.decode() if isinstance(value, bytes) else value).encode() + b"\x00"
            is_string = True
        elif encoding == "hex2bin":
            sval = value.decode() if isinstance(value, bytes) else value
            data = binascii.a2b_hex(sval.strip())
            is_string = False
        elif encoding == "base64":
            data = binascii.a2b_base64(value)
            is_string = False
        elif encoding == "binary":
            data = value if isinstance(value, bytes) else value.encode()
            is_string = False
        else:
            raise ValueError(f"unsupported encoding {encoding}")
        try:
            self._varlen(self.cur, key, data, is_string, ns)
        except PageFullError:
            self._varlen(self._new_page(), key, data, is_string, ns)

    def entry(self, key: str, encoding: str, value: str | bytes) -> None:
        """Equivalent of a CSV ``data`` row (incl. the tool's Wi-Fi extras)."""
        if len(key) > 15:
            raise ValueError(f"key {key!r} longer than 15 characters")
        if key in ("sta.ssid", "sta.pswd") and not self._wifi_extras:
            self._entry(key, value, encoding)
            for hkey, henc, hval in (
                ("sta.apinfo", "hex2bin", "f" * 280),
                ("sta.pmk", "hex2bin", "0" * 64),
                ("sta.apsw", "hex2bin", "0000"),
            ):
                self._entry(hkey, hval, henc)
            self._wifi_extras = True
            return
        self._entry(key, value, encoding)

    def rows(self, rows: list[tuple[str, str, str, str]]) -> NvsWriter:
        """Apply CSV-style rows ``(key, type, encoding, value)``."""
        for key, typ, enc, val in rows:
            if typ == "namespace":
                self.namespace(key)
            elif typ == "data":
                self.entry(key, enc, val)
            else:
                raise ValueError(f"unsupported row type {typ}")
        return self

    def to_bytes(self) -> bytes:
        while True:
            try:
                self._new_page(empty=True)
            except InsufficientSizeError:
                self.size_left = -1  # mimics ``self.size = None``
                self.page_num += 1
                self.pages.append(_Page(self.page_num))  # reserved page, all 0xFF
                break
        out = b"".join(bytes(p.buf) for p in self.pages)
        assert len(out) == self.total, (len(out), self.total)
        return out


def to_csv(rows: list[tuple[str, str, str, str]]) -> str:
    """Render rows in the CSV dialect read by nvs_partition_gen ``generate``."""
    lines = ["key,type,encoding,value"]
    for key, typ, enc, val in rows:
        lines.append(f"{key},{typ},{enc},{val}")
    return "\n".join(lines) + "\n"


def build_nvs(rows: list[tuple[str, str, str, str]], size: int = 0x6000) -> bytes:
    return NvsWriter(size).rows(rows).to_bytes()


def erase(
    data: bytes, nvs: NvsPartition, namespace: str, key: str, occurrence: int | None = None
) -> bytes:
    """Flip bitmap state 0b10 -> 0b00 for every slot of an item (incl. blob chunks).

    Mirrors what nvs_flash does on erase; nothing else (CRCs, data) is touched.
    ``occurrence`` selects one of several live copies of the key (0 = oldest), as left
    behind by a value update; ``None`` erases them all.
    """
    buf = bytearray(data)
    targets = sorted(
        (e for e in nvs.entries if e.namespace == namespace and e.key == key),
        key=lambda e: e.offset,
    )
    assert targets, (namespace, key)
    if occurrence is not None:
        targets = [targets[occurrence]]
    slots: list[tuple[int, int, int]] = []
    for e in targets:
        slots.append((e.page, e.slot, e.span))
        for ev in e.evidence[1:]:
            rel = ev.offset - nvs.offset
            page, off = divmod(rel, 4096)
            if off >= 64 and (off - 64) % 32 == 0 and ev.length % 32 == 0 and ev.length:
                slots.append((page, (off - 64) // 32, ev.length // 32))
    for page, slot, span in slots:
        for s in range(slot, slot + span):
            bit = s * 2
            buf[page * 4096 + 32 + bit // 8] &= ~(0b11 << (bit % 8)) & 0xFF
    return bytes(buf)


def nvs_keys_image(key: bytes, size: int = 0x1000) -> bytes:
    """nvs_keys partition: e_key || t_key, crc32(key, 0xFFFFFFFF), 0xFF fill (nvs gen layout)."""
    if len(key) != 64:
        raise ValueError("NVS key must be 64 bytes")
    body = key + struct.pack("<I", zlib.crc32(key, 0xFFFFFFFF) & 0xFFFFFFFF)
    return body + b"\xff" * (size - len(body))


def encrypt_nvs(plain: bytes, key: bytes) -> bytes:
    """Encrypt every written/erased entry slot like nvs_partition_gen ``encrypt``."""
    from flashtrace.crypto import nvs_crypt_entry  # noqa: PLC0415 - keep writer import-light

    buf = bytearray(plain)
    for p in range(len(buf) // PAGE_SIZE):
        page = p * PAGE_SIZE
        if buf[page : page + 4] == b"\xff\xff\xff\xff":
            continue
        for slot in range(MAX_ENTRIES):
            bit = slot * 2
            if (buf[page + 32 + bit // 8] >> (bit % 8)) & 0b11 == 0b11:
                continue
            off = page + FIRST_ENTRY_OFFSET + slot * ENTRY_SIZE
            buf[off : off + ENTRY_SIZE] = nvs_crypt_entry(
                bytes(buf[off : off + ENTRY_SIZE]), off, key, decrypt=False
            )
    return bytes(buf)
