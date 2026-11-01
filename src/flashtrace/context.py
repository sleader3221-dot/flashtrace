"""Analysis context: everything parsed from one dump, handed to every rule.

``build_context`` is pure and never raises on hostile input: each parser
records anomalies, and anything that cannot be parsed is simply absent.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from flashtrace.appimage import AppImage, parse_app_image
from flashtrace.coredump import CoreDump, parse_coredump
from flashtrace.fs import FsListing
from flashtrace.fs.littlefs import parse_littlefs
from flashtrace.fs.spiffs import parse_spiffs
from flashtrace.io import ChipDetection, detect_chip, is_blank, shannon_entropy
from flashtrace.model import Anomaly, ByteSource, Evidence, Segment, sha256_hex
from flashtrace.nvs import NvsPartition, parse_nvs
from flashtrace.otadata import OtaData, parse_otadata
from flashtrace.partition import (
    DEFAULT_TABLE_OFFSET,
    TYPE_APP,
    TYPE_DATA,
    PartitionEntry,
    PartitionTable,
    find_partition_table,
    layout_anomalies,
    parse_partition_table,
    partition_slice,
)

ENCRYPTION_ENTROPY_THRESHOLD = 7.5
SUBTYPE_OTA, SUBTYPE_NVS, SUBTYPE_COREDUMP, SUBTYPE_NVS_KEYS = 0x00, 0x02, 0x03, 0x04
SUBTYPE_SPIFFS, SUBTYPE_LITTLEFS = 0x82, 0x83


@dataclass(frozen=True)
class ScanRegion:
    """Bytes to scan for secrets plus how to map matches back to the dump."""

    label: str  # e.g. "app:ota_0", "file:/certs/key.pem", "nvs:wifi/sta.pswd"
    partition: str | None
    data: bytes
    segments: tuple[Segment, ...]
    source: str  # "app" | "partition" | "file" | "nvs"
    fallback: Evidence | None = None  # used when the bytes cannot be located precisely

    def evidence(self, dump: ByteSource, rel: int, length: int) -> tuple[Evidence, ...]:
        """Evidence for ``data[rel:rel+length]``: one item per dump segment touched."""
        mv = memoryview(dump)
        out: list[Evidence] = []
        end = rel + length
        for s in self.segments:
            lo, hi = max(rel, s.rel), min(end, s.rel + s.length)
            if lo >= hi:
                continue
            a = s.abs_offset + (lo - s.rel)
            a_end = min(a + (hi - lo), len(mv))
            a = min(a, a_end)
            out.append(Evidence(self.partition, a, a_end - a, sha256_hex(mv[a:a_end])))
        if not out and self.fallback is not None:
            return (self.fallback,)
        return tuple(out)


@dataclass(frozen=True)
class PartitionInfo:
    entry: PartitionEntry
    entropy: float
    sha256: str
    present: int  # bytes actually present in the dump (clamped)


@dataclass
class AnalysisContext:
    dump: bytes
    dump_sha256: str
    reveal_secrets: bool = False
    baselines: frozenset[str] = frozenset()  # app image SHA-256s considered known-good
    chip: ChipDetection | None = None
    table: PartitionTable | None = None
    table_offset: int | None = None
    partitions: dict[str, PartitionInfo] = field(default_factory=dict)
    apps: dict[str, AppImage] = field(default_factory=dict)
    otadata: OtaData | None = None
    nvs: dict[str, NvsPartition] = field(default_factory=dict)
    filesystems: dict[str, FsListing] = field(default_factory=dict)
    coredump: CoreDump | None = None
    encryption_likely: bool = False
    encryption_reason: str | None = None
    anomalies: list[tuple[str | None, Anomaly]] = field(default_factory=list)
    extra_regions: list[ScanRegion] = field(default_factory=list)

    # -- helpers -------------------------------------------------------------
    def ev(self, offset: int, length: int, partition: str | None) -> Evidence:
        mv = memoryview(self.dump)
        a = max(0, min(offset, len(mv)))
        b = max(a, min(offset + max(length, 0), len(mv)))
        return Evidence(partition, a, b - a, sha256_hex(mv[a:b]))

    def ota_slots(self) -> list[tuple[int, str, AppImage | None]]:
        """(slot number, label, parsed image) for every ota_N app partition."""
        if self.table is None:
            return []
        return [(e.subtype - 0x10, e.label, self.apps.get(e.label)) for e in self.table.ota_apps]

    def active_slot_label(self) -> str | None:
        if self.otadata is None or self.otadata.active_slot is None:
            return None
        for slot, label, _img in self.ota_slots():
            if slot == self.otadata.active_slot:
                return label
        return None

    def scan_regions(self) -> list[ScanRegion]:
        regions: list[ScanRegion] = []
        for label, img in self.apps.items():
            length = img.image_length or 0
            if not length:
                continue
            start = img.offset
            end = min(start + length, len(self.dump))
            regions.append(
                ScanRegion(
                    f"app:{label}",
                    label,
                    self.dump[start:end],
                    (Segment(0, start, end - start),),
                    "app",
                )
            )
        regions.extend(self.nvs_regions())
        regions.extend(self.fs_regions())
        regions.extend(self.raw_regions())
        regions.extend(self.extra_regions)
        return regions

    def fs_regions(self) -> list[ScanRegion]:
        out: list[ScanRegion] = []
        for label, fs in self.filesystems.items():
            if not fs.mounted:
                continue
            whole = self.ev(fs.offset, fs.size, label)
            for f in fs.files:
                out.append(ScanRegion(f"file:{f.path}", label, f.data, f.segments, "file", whole))
        return out

    def raw_regions(self) -> list[ScanRegion]:
        """Raw string sweep of data partitions that no structured parser explained."""
        if self.table is None:
            return []
        skip = {SUBTYPE_OTA, SUBTYPE_NVS, SUBTYPE_COREDUMP, SUBTYPE_NVS_KEYS, 0x01, 0x05}
        out: list[ScanRegion] = []
        for e in self.table.entries:
            if e.type != TYPE_DATA or e.subtype in skip:
                continue
            fs = self.filesystems.get(e.label)
            if fs is not None and fs.mounted:
                continue
            start = min(e.offset, len(self.dump))
            end = min(e.offset + e.size, len(self.dump))
            if end <= start or is_blank(self.dump[start:end]):
                continue
            out.append(
                ScanRegion(
                    f"partition:{e.label}",
                    e.label,
                    self.dump[start:end],
                    (Segment(0, start, end - start),),
                    "partition",
                )
            )
        return out

    def nvs_regions(self) -> list[ScanRegion]:
        """Live NVS string/blob values (Wi-Fi keys excluded: NVS.WIFI_CREDENTIALS owns them)."""
        out: list[ScanRegion] = []
        for label, nvs in self.nvs.items():
            for e in nvs.entries:
                if isinstance(e.value, int) or not e.payload or e.namespace == "nvs.net80211":
                    continue
                segs: list[Segment] = []
                rel = 0
                for pe in e.payload:
                    segs.append(Segment(rel, pe.offset, pe.length))
                    rel += pe.length
                data = b"".join(self.dump[s.abs_offset : s.abs_offset + s.length] for s in segs)
                out.append(ScanRegion(f"nvs:{e.qualified_key}", label, data, tuple(segs), "nvs"))
        return out


def _record(ctx: AnalysisContext, partition: str | None, anomalies: Iterable[Anomaly]) -> None:
    ctx.anomalies.extend((partition, a) for a in anomalies)


def build_context(
    dump: bytes,
    *,
    reveal_secrets: bool = False,
    baselines: Iterable[str] = (),
    table_offset: int = DEFAULT_TABLE_OFFSET,
    extra_parsers: Mapping[str, object] | None = None,
) -> AnalysisContext:
    """Parse a dump into an :class:`AnalysisContext` (no rules are run here)."""
    del extra_parsers  # reserved for phase B dispatch hooks
    ctx = AnalysisContext(
        dump=dump,
        dump_sha256=hashlib.sha256(dump).hexdigest(),
        reveal_secrets=reveal_secrets,
        baselines=frozenset(b.lower() for b in baselines),
    )
    ctx.chip = detect_chip(dump)
    if ctx.chip is not None:
        _record(ctx, None, ctx.chip.anomalies)

    off = find_partition_table(dump, table_offset)
    if off is None:
        region = dump[table_offset : table_offset + 0x10000] or dump[:0x10000]
        ent = shannon_entropy(region)
        if ent > ENCRYPTION_ENTROPY_THRESHOLD:
            ctx.encryption_likely = True
            ctx.encryption_reason = (
                f"no partition table magic at {table_offset:#x} and entropy"
                f" {ent:.2f} bits/byte > {ENCRYPTION_ENTROPY_THRESHOLD}"
            )
        else:
            ctx.anomalies.append(
                (
                    None,
                    Anomaly(
                        "PT_NOT_FOUND",
                        "no partition table found at the default offset or any 4 KB boundary",
                        table_offset,
                        0,
                    ),
                )
            )
        return ctx

    ctx.table_offset = off
    ctx.table = parse_partition_table(dump[off : off + 0xC00], off)
    _record(ctx, None, ctx.table.anomalies)
    _record(ctx, None, layout_anomalies(ctx.table, len(dump)))

    nvs_keys_present = bool(ctx.table.find(TYPE_DATA, SUBTYPE_NVS_KEYS))
    num_ota = len(ctx.table.ota_apps)
    for e in ctx.table.entries:
        part = partition_slice(dump, e)
        ctx.partitions.setdefault(
            e.label,
            PartitionInfo(e, shannon_entropy(part), sha256_hex(part), len(part)),
        )
        if e.type == TYPE_APP:
            img = parse_app_image(part, e.offset)
            if img is not None:
                ctx.apps[e.label] = img
                _record(ctx, e.label, img.anomalies)
        elif e.type == TYPE_DATA and e.subtype == SUBTYPE_OTA:
            ctx.otadata = parse_otadata(part, e.offset, num_ota)
            _record(ctx, e.label, ctx.otadata.anomalies)
        elif e.type == TYPE_DATA and e.subtype == SUBTYPE_NVS:
            nvs = parse_nvs(part, e.offset, e.label, nvs_keys_present=nvs_keys_present)
            ctx.nvs[e.label] = nvs
            _record(ctx, e.label, nvs.anomalies)
        elif e.type == TYPE_DATA and e.subtype in (SUBTYPE_SPIFFS, SUBTYPE_LITTLEFS):
            if is_blank(part):
                continue  # erased filesystem partition: nothing to list
            parser = parse_spiffs if e.subtype == SUBTYPE_SPIFFS else parse_littlefs
            fs = parser(part, e.offset, e.label)
            ctx.filesystems[e.label] = fs
            _record(ctx, e.label, fs.anomalies)
        elif e.type == TYPE_DATA and e.subtype == SUBTYPE_COREDUMP:
            ctx.coredump = parse_coredump(part, e.offset, e.label)
            _record(ctx, e.label, ctx.coredump.anomalies)
    return ctx
