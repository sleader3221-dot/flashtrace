from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from flashtrace.fs.spiffs import looks_like_spiffs, parse_spiffs
from tools.corpus.spiffs_writer import build_spiffs

FILES = [
    ("/a.txt", b"hello"),
    ("/certs/device.pem", b"K" * 1000),
    ("/empty", b""),
    ("/bin/blob.bin", bytes(range(256)) * 120),  # > one index page worth of data pages
]
SIZE = 0x20000
BASE = 0x310000


def test_round_trip() -> None:
    img = build_spiffs(FILES, SIZE)
    assert len(img) == SIZE and looks_like_spiffs(img)
    fs = parse_spiffs(img, BASE, "spiffs")
    assert fs.mounted and fs.anomalies == ()
    assert {f.path: f.data for f in fs.files} == dict(FILES)
    for f in fs.files:
        assert f.complete and f.located
        joined = b"".join(
            img[s.abs_offset - BASE : s.abs_offset - BASE + s.length] for s in f.segments
        )
        assert joined == f.data and sum(s.length for s in f.segments) == f.size


def test_not_spiffs_reports_anomaly() -> None:
    fs = parse_spiffs(os.urandom(SIZE), BASE, "spiffs")
    assert not fs.mounted and fs.files == ()
    assert [a.kind for a in fs.anomalies] == ["FS_SPIFFS_UNRECOGNISED"]
    assert not parse_spiffs(b"", 0).mounted


def test_missing_data_page_marks_incomplete() -> None:
    img = bytearray(build_spiffs([("/x.bin", b"Z" * 2000)], SIZE))
    # wipe the lookup entry of the 3rd data page (block 0, page 4) -> treated as free
    img[3 * 2 : 3 * 2 + 2] = b"\xff\xff"
    fs = parse_spiffs(bytes(img), BASE, "spiffs")
    [f] = fs.files
    assert not f.complete and f.data == b"Z" * 251 * 2
    assert [a.kind for a in fs.anomalies] == ["FS_SPIFFS_INCOMPLETE"]


def spiffsgen_path() -> Path:
    p = os.environ.get("FLASHTRACE_SPIFFSGEN")
    if p and Path(p).is_file():
        return Path(p)
    if os.environ.get("FLASHTRACE_REQUIRE_TOOLS") == "1":
        pytest.fail("FLASHTRACE_SPIFFSGEN must point at ESP-IDF spiffsgen.py in CI", pytrace=False)
    pytest.skip("spiffsgen.py not available")


def test_writer_is_byte_identical_to_spiffsgen(tmp_path: Path) -> None:
    gen = spiffsgen_path()
    root = tmp_path / "root"
    for name, data in FILES:
        p = root / name.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    out = tmp_path / "spiffs.bin"
    proc = subprocess.run(
        [sys.executable, str(gen), hex(SIZE), str(root), str(out)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    # replicate spiffsgen's os.walk order exactly
    order = []
    for r, _d, fnames in os.walk(root):
        for f in fnames:
            full = Path(r) / f
            order.append(("/" + full.relative_to(root).as_posix(), full.read_bytes()))
    ref = out.read_bytes()
    assert build_spiffs(order, SIZE) == ref
    fs = parse_spiffs(ref, 0, "spiffs")
    assert {f.path: f.data for f in fs.files} == dict(FILES)
