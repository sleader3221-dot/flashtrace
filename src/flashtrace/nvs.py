"""NVS (non-volatile storage) partition parser, including ERASED-entry recovery.

Format confirmed against ESP-IDF v5.3.1 ``nvs_flash/src/nvs_page.hpp``,
``nvs_types.{hpp,cpp}`` and esp-idf-nvs-partition-gen 0.2.0:

* 4096-byte pages. Header (32 B): state u32, seq u32, version u8 (0xFE = v2
  multipage blobs, 0xFF = v1), reserved[19] (0xFF), crc32 u32 over bytes 4..28.
  Page states: 0xFFFFFFFF uninitialised, 0xFFFFFFFE ACTIVE, 0xFFFFFFFC FULL,
  0xFFFFFFF8 FREEING, 0xFFFFFFF0 CORRUPT, 0 INVALID.
* Entry-state bitmap (32 B): 2 bits per entry, entry n at bits 2n..2n+1 of the
  little-endian bit stream. 0b11 EMPTY, 0b10 WRITTEN, 0b00 ERASED, 0b01 ILLEGAL.
* 126 entries x 32 B: ns_index u8, type u8, span u8, chunk_index u8, crc32 u32,
  key[16], data[8]. Header CRC = crc32(entry[0:4] + entry[8:32], 0xFFFFFFFF)
  (``esp_rom_crc32_le(0xffffffff, ...)`` == ``zlib.crc32(..., 0xFFFFFFFF)``).
* Variable-length items (STR 0x21, legacy BLOB 0x41, BLOB_DATA 0x42): data[0:2]
  size u16, data[4:8] crc32 of the payload, payload in the following span-1 slots.
* BLOB_IDX 0x48: data[0:4] total size u32, data[4] chunk_count, data[5]
  chunk_start (0x00 or 0x80); chunks are BLOB_DATA with chunk_index
  chunk_start .. chunk_start+count-1.
* Namespaces: entries with ns_index 0 map name (key) -> index (u8 value).
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from flashtrace.io import shannon_entropy
from flashtrace.model import Anomaly, ByteSource, Evidence, sha256_hex

PAGE_SIZE = 4096
ENTRY_SIZE = 32
ENTRIES_PER_PAGE = 126
FIRST_ENTRY = 64

PAGE_STATES: dict[int, str] = {
    0xFFFFFFFF: "UNINITIALIZED",
    0xFFFFFFFE: "ACTIVE",
    0xFFFFFFFC: "FULL",
    0xFFFFFFF8: "FREEING",
    0xFFFFFFF0: "CORRUPT",
    0x00000000: "INVALID",
}
PARSEABLE_STATES = {"ACTIVE", "FULL", "FREEING", "CORRUPT"}

ES_EMPTY, ES_WRITTEN, ES_ERASED, ES_ILLEGAL = 0b11, 0b10, 0b00, 0b01

U8, I8, U16, I16, U32, I32, U64, I64 = 0x01, 0x11, 0x02, 0x12, 0x04, 0x14, 0x08, 0x18
STR, BLOB, BLOB_DATA, BLOB_IDX = 0x21, 0x41, 0x42, 0x48
INT_TYPES: dict[int, tuple[str, str]] = {
    U8: ("U8", "<B"),
    I8: ("I8", "<b"),
    U16: ("U16", "<H"),
    I16: ("I16", "<h"),
    U32: ("U32", "<I"),
    I32: ("I32", "<i"),
    U64: ("U64", "<Q"),
    I64: ("I64", "<q"),
}
VARLEN_TYPES = {STR: "STR", BLOB: "BLOB", BLOB_DATA: "BLOB_DATA"}
TYPE_NAMES = {**{k: v[0] for k, v in INT_TYPES.items()}, **VARLEN_TYPES, BLOB_IDX: "BLOB_IDX"}

EntryStatus = Literal["written", "erased"]
Value = int | str | bytes


def nvs_crc32(data: ByteSource) -> int:
    return zlib.crc32(data, 0xFFFFFFFF) & 0xFFFFFFFF


def _ev(data: memoryview, rel: int, length: int, base: int, partition: str | None) -> Evidence:
    rel = max(0, min(rel, len(data)))
    end = max(rel, min(rel + max(length, 0), len(data)))
    return Evidence(partition, base + rel, end - rel, sha256_hex(data[rel:end]))


@dataclass(frozen=True)
class NvsPage:
    index: int
    offset: int  # absolute
    state: int
    state_name: str
    seq: int
    version: int
    crc_stored: int
    crc_computed: int

    @property
    def header_crc_ok(self) -> bool:
        return self.crc_stored == self.crc_computed


@dataclass(frozen=True)
class NvsEntry:
    status: EntryStatus
    page: int
    slot: int
    offset: int  # absolute offset of the 32-byte header entry
    ns_index: int
    namespace: str | None
    key: str
    type: int
    span: int
    chunk_index: int
    header_crc_ok: bool
    data_crc_ok: bool | None  # None for fixed-size types
    value: Value | None  # None when the value could not be recovered
    evidence: tuple[Evidence, ...]  # header(+span) bytes, then payload bytes
    value_sha256: str | None = None  # SHA-256 of the raw value bytes (verifiable)
    chunks: tuple[int, ...] = ()  # for reassembled blobs: chunk indices used
    complete: bool = True  # reassembled blob had all chunks
    payload: tuple[Evidence, ...] = ()  # evidence of the value bytes only, in order

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"{self.type:#04x}")

    @property
    def qualified_key(self) -> str:
        return f"{self.namespace or f'ns#{self.ns_index}'}/{self.key}"


@dataclass(frozen=True)
class NvsPartition:
    offset: int
    size: int
    partition: str | None
    entropy: float
    encrypted: bool
    encryption_reason: str | None
    pages: tuple[NvsPage, ...]
    namespaces: dict[int, str]
    entries: tuple[NvsEntry, ...]  # live (WRITTEN) values; blobs reassembled
    recovered_deleted: tuple[NvsEntry, ...]  # ERASED values recovered from flash
    anomalies: tuple[Anomaly, ...] = field(default_factory=tuple)

    def get(self, namespace: str, key: str) -> list[NvsEntry]:
        return [e for e in self.entries if e.namespace == namespace and e.key == key]


@dataclass
class _Raw:
    status: EntryStatus
    page: int
    slot: int
    rel: int  # offset of header relative to partition start
    raw: bytes
    span: int
    header_crc_ok: bool


def _bitmap_state(bitmap: bytes, slot: int) -> int:
    bit = slot * 2
    return (bitmap[bit // 8] >> (bit % 8)) & 0b11


def _decode_key(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="backslashreplace")


def parse_nvs(
    data: ByteSource,
    base_offset: int = 0,
    partition: str | None = None,
    *,
    nvs_keys_present: bool = False,
) -> NvsPartition:
    """Parse an NVS partition. Never raises on malformed input."""
    mv = memoryview(data)
    entropy = shannon_entropy(mv)
    anomalies: list[Anomaly] = []
    pages: list[NvsPage] = []
    raws: list[_Raw] = []

    n_pages = len(mv) // PAGE_SIZE
    if len(mv) % PAGE_SIZE:
        anomalies.append(
            Anomaly(
                "NVS_PARTIAL_PAGE",
                f"NVS region size {len(mv)} is not a multiple of {PAGE_SIZE}",
                base_offset + n_pages * PAGE_SIZE,
                len(mv) - n_pages * PAGE_SIZE,
            )
        )
    valid_headers = 0
    for p in range(n_pages):
        rel = p * PAGE_SIZE
        state, seq, version = struct.unpack_from("<IIB", mv, rel)
        (crc_stored,) = struct.unpack_from("<I", mv, rel + 28)
        page = NvsPage(
            index=p,
            offset=base_offset + rel,
            state=state,
            state_name=PAGE_STATES.get(state, "UNKNOWN"),
            seq=seq,
            version=version,
            crc_stored=crc_stored,
            crc_computed=nvs_crc32(mv[rel + 4 : rel + 28]),
        )
        if page.state_name == "UNINITIALIZED":
            if any(b != 0xFF for b in mv[rel : rel + PAGE_SIZE]):
                anomalies.append(
                    Anomaly(
                        "NVS_UNINITIALIZED_PAGE_NOT_BLANK",
                        f"page {p} is marked uninitialised but contains data",
                        base_offset + rel,
                        PAGE_SIZE,
                        {"page": p},
                    )
                )
            continue
        pages.append(page)
        if page.header_crc_ok and page.state_name in PARSEABLE_STATES:
            valid_headers += 1
        if not page.header_crc_ok:
            anomalies.append(
                Anomaly(
                    "NVS_PAGE_HEADER_CRC",
                    f"page {p} header CRC {crc_stored:#010x} != {page.crc_computed:#010x}",
                    base_offset + rel,
                    32,
                    {"page": p},
                )
            )
        if page.state_name not in PARSEABLE_STATES:
            anomalies.append(
                Anomaly(
                    "NVS_PAGE_STATE",
                    f"page {p} has state {page.state_name} ({state:#010x})",
                    base_offset + rel,
                    4,
                    {"page": p, "state": state},
                )
            )
            continue
        raws.extend(_scan_page(mv, rel, p, base_offset, anomalies))

    # --- encryption detection (do not parse) --------------------------------
    reason: str | None = None
    written = [r for r in raws if r.status == "written"]
    if valid_headers == 0 and n_pages and entropy > 7.5:
        reason = f"no valid NVS page headers and entropy {entropy:.2f} bits/byte"
    elif nvs_keys_present and written and sum(r.header_crc_ok for r in written) == 0:
        reason = "nvs_keys partition present and no written entry has a valid CRC"
    if reason is not None:
        return NvsPartition(
            offset=base_offset,
            size=len(mv),
            partition=partition,
            entropy=entropy,
            encrypted=True,
            encryption_reason=reason,
            pages=tuple(pages),
            namespaces={},
            entries=(),
            recovered_deleted=(),
            anomalies=(),
        )

    namespaces: dict[int, str] = {}
    for r in raws:
        if r.status == "written" and r.raw[0] == 0 and r.raw[1] == U8 and r.header_crc_ok:
            namespaces[r.raw[24]] = _decode_key(r.raw[8:24])
    # erased namespace definitions still tell us names for orphaned indices
    for r in raws:
        if r.status == "erased" and r.raw[0] == 0 and r.raw[1] == U8:
            namespaces.setdefault(r.raw[24], _decode_key(r.raw[8:24]))

    live = _build_entries(mv, base_offset, partition, raws, "written", namespaces, anomalies)
    deleted = _build_entries(mv, base_offset, partition, raws, "erased", namespaces, None)
    return NvsPartition(
        offset=base_offset,
        size=len(mv),
        partition=partition,
        entropy=entropy,
        encrypted=False,
        encryption_reason=None,
        pages=tuple(pages),
        namespaces=namespaces,
        entries=tuple(live),
        recovered_deleted=tuple(deleted),
        anomalies=tuple(anomalies),
    )


def _scan_page(
    mv: memoryview, rel: int, p: int, base: int, anomalies: list[Anomaly]
) -> Iterable[_Raw]:
    bitmap = bytes(mv[rel + 32 : rel + 64])
    slot = 0
    while slot < ENTRIES_PER_PAGE:
        st = _bitmap_state(bitmap, slot)
        if st == ES_EMPTY:
            slot += 1
            continue
        erel = rel + FIRST_ENTRY + slot * ENTRY_SIZE
        if st == ES_ILLEGAL:
            anomalies.append(
                Anomaly(
                    "NVS_ILLEGAL_ENTRY_STATE",
                    f"page {p} entry {slot} has illegal bitmap state 0b01",
                    base + erel,
                    ENTRY_SIZE,
                    {"page": p, "slot": slot},
                )
            )
            slot += 1
            continue
        raw = bytes(mv[erel : erel + ENTRY_SIZE])
        status: EntryStatus = "written" if st == ES_WRITTEN else "erased"
        if raw == b"\xff" * ENTRY_SIZE:
            # erased/written state but blank slot: span slot of an earlier item
            slot += 1
            continue
        crc_ok = struct.unpack_from("<I", raw, 4)[0] == nvs_crc32(raw[0:4] + raw[8:32])
        if status == "erased" and not crc_ok:
            # erased payload slot or damaged header: nothing trustworthy to recover
            slot += 1
            continue
        span = raw[2]
        max_span = ENTRIES_PER_PAGE - slot
        if not 1 <= span <= max_span:
            if status == "written":
                anomalies.append(
                    Anomaly(
                        "NVS_BAD_SPAN",
                        f"page {p} entry {slot} has span {span} (max {max_span})",
                        base + erel,
                        ENTRY_SIZE,
                        {"page": p, "slot": slot, "span": span},
                    )
                )
            span = 1
        if status == "written" and not crc_ok:
            anomalies.append(
                Anomaly(
                    "NVS_ENTRY_CRC",
                    f"page {p} entry {slot} header CRC mismatch",
                    base + erel,
                    ENTRY_SIZE,
                    {"page": p, "slot": slot},
                )
            )
        yield _Raw(status, p, slot, erel, raw, span, crc_ok)
        slot += span if crc_ok else 1


def _varlen_payload(
    mv: memoryview, r: _Raw, base: int, partition: str | None
) -> tuple[bytes, bool, Evidence | None]:
    size = struct.unpack_from("<H", r.raw, 24)[0]
    crc = struct.unpack_from("<I", r.raw, 28)[0]
    cap = (r.span - 1) * ENTRY_SIZE
    start = r.rel + ENTRY_SIZE
    size = min(size, cap, max(0, len(mv) - start))
    payload = bytes(mv[start : start + size])
    ev = _ev(mv, start, size, base, partition) if size else None
    return payload, nvs_crc32(payload) == crc, ev


def _build_entries(
    mv: memoryview,
    base: int,
    partition: str | None,
    raws: list[_Raw],
    status: EntryStatus,
    namespaces: dict[int, str],
    anomalies: list[Anomaly] | None,
) -> list[NvsEntry]:
    out: list[NvsEntry] = []
    chunks: dict[tuple[int, str, int], list[tuple[_Raw, bytes, bool, Evidence | None]]] = {}
    for r in raws:
        if r.status != status:
            continue
        ns, typ = r.raw[0], r.raw[1]
        if ns == 0:
            continue  # namespace definition, not a value
        key = _decode_key(r.raw[8:24])
        hdr_ev = _ev(mv, r.rel, r.span * ENTRY_SIZE, base, partition)

        def mk(
            data_crc_ok: bool | None,
            value: Value,
            evidence: tuple[Evidence, ...],
            value_sha256: str,
            payload: tuple[Evidence, ...],
            r: _Raw = r,
            ns: int = ns,
            key: str = key,
            typ: int = typ,
        ) -> NvsEntry:
            return NvsEntry(
                status=status,
                page=r.page,
                slot=r.slot,
                offset=base + r.rel,
                ns_index=ns,
                namespace=namespaces.get(ns),
                key=key,
                type=typ,
                span=r.span,
                chunk_index=r.raw[3],
                header_crc_ok=r.header_crc_ok,
                data_crc_ok=data_crc_ok,
                value=value,
                evidence=evidence,
                value_sha256=value_sha256,
                payload=payload,
            )

        if typ in INT_TYPES:
            _name, fmt = INT_TYPES[typ]
            size = struct.calcsize(fmt)
            (val,) = struct.unpack_from(fmt, r.raw, 24)
            vev = _ev(mv, r.rel + 24, size, base, partition)
            out.append(mk(None, int(val), (hdr_ev,), sha256_hex(r.raw[24 : 24 + size]), (vev,)))
        elif typ in (STR, BLOB):
            payload, ok, pev = _varlen_payload(mv, r, base, partition)
            value: Value = (
                payload.split(b"\x00", 1)[0].decode("utf-8", errors="backslashreplace")
                if typ == STR
                else payload
            )
            if anomalies is not None and not ok:
                anomalies.append(
                    Anomaly(
                        "NVS_DATA_CRC",
                        f"payload CRC mismatch for {key!r}",
                        base + r.rel,
                        r.span * ENTRY_SIZE,
                        {"key": key, "page": r.page, "slot": r.slot},
                    )
                )
            pl = (pev,) if pev else ()
            out.append(mk(ok, value, (hdr_ev, *pl), sha256_hex(payload), pl))
        elif typ == BLOB_DATA:
            payload, ok, pev = _varlen_payload(mv, r, base, partition)
            chunks.setdefault((ns, key, r.raw[3]), []).append((r, payload, ok, pev))
            if anomalies is not None and not ok:
                anomalies.append(
                    Anomaly(
                        "NVS_DATA_CRC",
                        f"blob chunk CRC mismatch for {key!r}",
                        base + r.rel,
                        r.span * ENTRY_SIZE,
                        {"key": key, "chunk": r.raw[3]},
                    )
                )
        elif typ == BLOB_IDX:
            pass  # resolved below once all chunks are known
        elif anomalies is not None:
            anomalies.append(
                Anomaly(
                    "NVS_UNKNOWN_TYPE",
                    f"entry {key!r} has unknown type {typ:#04x}",
                    base + r.rel,
                    ENTRY_SIZE,
                    {"key": key, "type": typ},
                )
            )

    used: set[tuple[int, str, int]] = set()
    for r in raws:
        if r.status != status or r.raw[0] == 0 or r.raw[1] != BLOB_IDX:
            continue
        ns = r.raw[0]
        key = _decode_key(r.raw[8:24])
        total, count, start = struct.unpack_from("<IBB", r.raw, 24)
        parts: list[bytes] = []
        evs: list[Evidence] = [_ev(mv, r.rel, ENTRY_SIZE, base, partition)]
        oks: list[bool] = []
        idxs: list[int] = []
        pls: list[Evidence] = []
        complete = True
        for ci in range(start, min(start + count, 256)):
            cands = chunks.get((ns, key, ci))
            if not cands:
                complete = False
                continue
            # prefer a CRC-valid chunk; if several, the last one written
            cands_sorted = sorted(cands, key=lambda c: (c[2], c[0].page, c[0].slot))
            cr, payload, ok, pev = cands_sorted[-1]
            used.add((ns, key, ci))
            parts.append(payload)
            oks.append(ok)
            idxs.append(ci)
            evs.append(_ev(mv, cr.rel, ENTRY_SIZE, base, partition))
            if pev:
                evs.append(pev)
                pls.append(pev)
        blob = b"".join(parts)
        if len(blob) != total:
            complete = False
            blob = blob[:total]
        if anomalies is not None and not complete:
            anomalies.append(
                Anomaly(
                    "NVS_BLOB_INCOMPLETE",
                    f"blob {key!r} declares {total} bytes in {count} chunks;"
                    f" reassembled {len(blob)}",
                    base + r.rel,
                    ENTRY_SIZE,
                    {"key": key, "declared": total, "recovered": len(blob)},
                )
            )
        out.append(
            NvsEntry(
                status=status,
                page=r.page,
                slot=r.slot,
                offset=base + r.rel,
                ns_index=ns,
                namespace=namespaces.get(ns),
                key=key,
                type=BLOB_IDX,
                span=r.span,
                chunk_index=r.raw[3],
                header_crc_ok=r.header_crc_ok,
                data_crc_ok=all(oks) if oks else None,
                value=blob,
                evidence=tuple(evs),
                value_sha256=sha256_hex(blob),
                chunks=tuple(idxs),
                complete=complete,
                payload=tuple(pls),
            )
        )
    # chunks with no index entry (index erased/lost): surface them individually
    for (ns, key, ci), cands in chunks.items():
        if (ns, key, ci) in used:
            continue
        for cr, payload, ok, pev in cands:
            out.append(
                NvsEntry(
                    status=status,
                    page=cr.page,
                    slot=cr.slot,
                    offset=base + cr.rel,
                    ns_index=ns,
                    namespace=namespaces.get(ns),
                    key=key,
                    type=BLOB_DATA,
                    span=cr.span,
                    chunk_index=ci,
                    header_crc_ok=cr.header_crc_ok,
                    data_crc_ok=ok,
                    value=payload,
                    evidence=(_ev(mv, cr.rel, ENTRY_SIZE, base, partition),)
                    + ((pev,) if pev else ()),
                    value_sha256=sha256_hex(payload),
                    chunks=(ci,),
                    complete=False,
                    payload=(pev,) if pev else (),
                )
            )
    out.sort(key=lambda e: e.offset)
    return out
