import struct

from flashtrace.coredump import parse_coredump

SIZE = 0x10000


def test_empty() -> None:
    c = parse_coredump(b"\xff" * SIZE, 0x3F0000, "coredump")
    assert c.format == "empty" and not c.present and c.anomalies == ()


def test_binary_format() -> None:
    hdr = struct.pack("<IIIIII", 0x800, (0x0000 << 16) | 0x0003, 5, 0x15C, 2, 3)
    c = parse_coredump(hdr + b"\x00" * (SIZE - 24), 0x3F0000, "coredump")
    assert c.format == "binary" and c.tasks_num == 5 and c.data_len == 0x800
    assert c.version == 3 and c.present


def test_elf_format() -> None:
    hdr = struct.pack("<II", 0x900, (0x0005 << 16) | 0x0103)
    body = hdr + b"\x00" * 16 + b"\x7fELF\x01\x01\x01" + b"\x00" * 64
    c = parse_coredump(body + b"\xff" * (SIZE - len(body)), 0x3F0000, "coredump")
    assert c.format == "elf" and c.elf_offset == 0x3F0000 + 24 and c.chip_id == 5
    assert c.tasks_num is None


def test_hostile_header() -> None:
    hdr = struct.pack("<III", 0xFFFFFFF0, 0x0001, 999999)
    c = parse_coredump(hdr + b"\x00" * 100, 0, "coredump")
    assert c.format == "binary" and c.tasks_num is None
    assert {a.kind for a in c.anomalies} == {"CORE_BAD_LENGTH", "CORE_BAD_TASK_COUNT"}
    assert parse_coredump(b"\x01\x02", 0).format == "unknown"
