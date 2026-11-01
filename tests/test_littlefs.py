from __future__ import annotations

from typing import Any

import pytest

from flashtrace.fs.littlefs import parse_littlefs
from tests.conftest import require_module

lfs: Any = require_module("littlefs")

TREE = {
    "/config/app.json": b'{"mode": "prod"}\n' * 4,
    "/config/empty.txt": b"",
    "/data/nested/deep/blob.bin": bytes(range(256)) * 40,
    "/readme.txt": b"plain text file for flashtrace tests",
}


def build(block_size: int, blocks: int) -> bytes:
    fs = lfs.LittleFS(block_size=block_size, block_count=blocks)
    for path, data in TREE.items():
        parent = path.rsplit("/", 1)[0]
        if parent:
            fs.makedirs(parent, exist_ok=True)
        with fs.open(path, "wb") as fh:
            fh.write(data)
    return bytes(fs.context.buffer)


@pytest.mark.parametrize(("bs", "count"), [(4096, 32), (512, 256)])
def test_round_trip(bs: int, count: int) -> None:
    img = build(bs, count)
    listing = parse_littlefs(img, 0x310000, "littlefs")
    assert listing.mounted and listing.detail == f"block_size={bs}"
    assert {f.path: f.data for f in listing.files} == TREE
    assert {"/config", "/data", "/data/nested", "/data/nested/deep"} <= set(listing.directories)
    for f in listing.files:
        if f.located:
            s = f.segments[0]
            assert img[s.abs_offset - 0x310000 : s.abs_offset - 0x310000 + s.length] == f.data


def test_garbage_does_not_mount_and_buffer_is_not_formatted() -> None:
    junk = bytes([0x5A]) * (4096 * 8)
    listing = parse_littlefs(junk, 0, "littlefs")
    assert not listing.mounted and listing.anomalies[0].kind == "FS_LITTLEFS_UNMOUNTABLE"
    assert junk == bytes([0x5A]) * (4096 * 8)
