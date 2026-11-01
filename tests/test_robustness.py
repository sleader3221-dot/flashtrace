"""Deterministic robustness sweep (stdlib only, always runs).

Complements the hypothesis fuzzing in ``test_fuzz.py``: every truncation of each
fixture plus seeded random mutations and random blobs must parse without raising,
and every anomaly must point inside the bytes the parser was given.
"""

from __future__ import annotations

import random

import pytest

from tests.fixtures.generator import (
    DEFAULT_LAYOUT,
    app_image,
    bootloader_image,
    otadata,
    otadata_entry,
    partition_table,
    sig_block,
)
from tests.fixtures.nvs_cases import ROWS
from tests.parse_all import run_all_parsers
from tools.corpus.nvs_writer import build_nvs
from tools.corpus.spiffs_writer import build_spiffs

FIXTURES = {
    "app": app_image(),
    "app_signed": app_image() + b"\xff" * 2000 + sig_block(),
    "bootloader": bootloader_image("esp32s3"),
    "table": partition_table(list(DEFAULT_LAYOUT))[:256],
    "otadata": otadata((otadata_entry(1, 2), otadata_entry(2, 1))),
    "nvs": build_nvs(ROWS, 0x6000)[:0x3000],
    "spiffs": build_spiffs(
        [("/k.pem", b"-----BEGIN PRIVATE KEY-----\nAA==\n"), ("/a", b"x" * 600)], 0x2000
    ),
    "coredump": b"\x00\x08\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00" + b"\x00" * 52,
}


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_every_truncation(name: str) -> None:
    raw = FIXTURES[name]
    step = max(1, len(raw) // 2000)
    for n in range(0, len(raw) + 1, step):
        run_all_parsers(raw[:n])


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_random_mutations(name: str) -> None:
    rng = random.Random(f"flashtrace-{name}")
    raw = FIXTURES[name]
    for _ in range(120):
        buf = bytearray(raw)
        for _ in range(rng.randint(1, 8)):
            pos = rng.randrange(len(buf))
            buf[pos] = rng.randrange(256)
        cut = rng.randint(0, len(buf))
        run_all_parsers(bytes(buf[:cut]))
        run_all_parsers(bytes(buf))


def test_random_blobs() -> None:
    rng = random.Random(1234)
    for _ in range(300):
        n = rng.choice([0, 1, 7, 24, 31, 32, 33, 255, 4096, 8192])
        blob = bytes(rng.randrange(256) for _ in range(n))
        run_all_parsers(blob)
        run_all_parsers(b"\xe9" + blob)  # always reach the image header path
        run_all_parsers(b"\xaa\x50" + blob)  # always reach the table entry path
