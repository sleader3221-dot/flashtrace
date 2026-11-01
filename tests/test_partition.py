import struct

from flashtrace.partition import (
    find_partition_table,
    layout_anomalies,
    parse_partition_table,
    partition_slice,
)
from tests.fixtures.generator import DEFAULT_LAYOUT, Part, default_dump, partition_table


def kinds(anoms: tuple[object, ...]) -> list[str]:
    return [a.kind for a in anoms]  # type: ignore[attr-defined]


def test_parse_default_table() -> None:
    t = parse_partition_table(partition_table(list(DEFAULT_LAYOUT)), 0x8000)
    assert t.anomalies == ()
    assert t.end_marker_found and t.md5_present and t.md5_valid is True
    assert [(e.label, e.type, e.subtype, e.offset, e.size) for e in t.entries] == [
        (p.label, p.type, p.subtype, p.offset, p.size) for p in DEFAULT_LAYOUT
    ]
    assert t.entries[1].entry_offset == 0x8000 + 32
    assert t.md5_entry_offset == 0x8000 + 32 * len(DEFAULT_LAYOUT)
    assert t.length == 32 * (len(DEFAULT_LAYOUT) + 2)
    assert [e.label for e in t.ota_apps] == ["ota_0", "ota_1"]
    ota0 = t.by_label("ota_0")
    assert ota0 is not None and ota0.type_name == "app" and ota0.subtype_name == "ota_0"
    spiffs = t.by_label("spiffs")
    assert spiffs is not None and spiffs.subtype_name == "spiffs"
    assert t.by_label("nope") is None
    assert [e.label for e in t.find(1, 0x02)] == ["nvs"]


def test_flags_and_unknown_subtypes() -> None:
    parts = [Part("x", 1, 0x99, 0x9000, 0x1000, flags=0b11), Part("y", 0x40, 0x01, 0xA000, 0x1000)]
    t = parse_partition_table(partition_table(parts))
    x, y = t.entries
    assert x.encrypted and x.readonly and x.subtype_name == "0x99"
    assert y.type_name == "0x40" and not y.encrypted


def test_no_md5() -> None:
    t = parse_partition_table(partition_table(list(DEFAULT_LAYOUT), md5=False))
    assert not t.md5_present and t.md5_valid is None and t.anomalies == ()


def test_md5_mismatch() -> None:
    t = parse_partition_table(partition_table(list(DEFAULT_LAYOUT), corrupt_md5=True), 0x8000)
    assert t.md5_valid is False
    assert kinds(t.anomalies) == ["PT_MD5_MISMATCH"]
    assert t.anomalies[0].offset == t.md5_entry_offset


def test_md5_detects_tampered_entry() -> None:
    raw = bytearray(partition_table(list(DEFAULT_LAYOUT)))
    struct.pack_into("<L", raw, 3 * 32 + 4, 0x20000)  # move ota_0 without fixing MD5
    t = parse_partition_table(bytes(raw))
    assert t.md5_valid is False and "PT_MD5_MISMATCH" in kinds(t.anomalies)


def test_missing_end_marker_and_bad_magic() -> None:
    raw = partition_table(list(DEFAULT_LAYOUT), md5=False)
    no_end = raw[: 32 * len(DEFAULT_LAYOUT)]
    t = parse_partition_table(no_end)
    assert len(t.entries) == len(DEFAULT_LAYOUT)
    assert kinds(t.anomalies) == ["PT_NO_END_MARKER"]

    bad = bytearray(raw)
    bad[2 * 32 : 2 * 32 + 2] = b"\x00\x00"
    t = parse_partition_table(bytes(bad))
    assert len(t.entries) == 2 and kinds(t.anomalies) == ["PT_BAD_ENTRY_MAGIC"]


def test_find_partition_table() -> None:
    dump = bytearray(default_dump())
    assert find_partition_table(dump) == 0x8000
    tbl = bytes(dump[0x8000:0x8C00])
    dump[0x8000:0x8C00] = b"\xff" * 0xC00
    dump[0xA000:0xAC00] = tbl
    assert find_partition_table(dump) == 0xA000
    assert find_partition_table(b"\xff" * 0x10000) is None


def test_layout_anomalies() -> None:
    parts = [
        Part("a", 1, 2, 0x9000, 0x2000),
        Part("b", 1, 2, 0xA000, 0x1000),  # overlaps a
        Part("c", 0, 0x10, 0x3F0000, 0x20000),  # beyond 4 MB
    ]
    t = parse_partition_table(partition_table(parts), 0x8000)
    an = layout_anomalies(t, 0x400000)
    assert sorted(kinds(an)) == ["PT_OUT_OF_BOUNDS", "PT_OVERLAP"]
    assert (
        layout_anomalies(parse_partition_table(partition_table(list(DEFAULT_LAYOUT))), 0x400000)
        == ()
    )


def test_partition_slice_is_clamped() -> None:
    t = parse_partition_table(partition_table([Part("c", 0, 0x10, 0xF000, 0x2000)]))
    assert len(partition_slice(b"\x00" * 0x10000, t.entries[0])) == 0x1000
    assert len(partition_slice(b"\x00" * 0x100, t.entries[0])) == 0
