"""Hypothesis fuzzing: no parser may crash on random, mutated or truncated input."""

from __future__ import annotations

from tests.conftest import require_module

require_module("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from tests.fixtures.generator import (  # noqa: E402
    DEFAULT_LAYOUT,
    app_image,
    default_dump,
    otadata,
    otadata_entry,
    partition_table,
)
from tests.fixtures.nvs_cases import ROWS  # noqa: E402
from tests.parse_all import run_all_parsers  # noqa: E402
from tools.corpus.nvs_writer import build_nvs  # noqa: E402
from tools.corpus.spiffs_writer import build_spiffs  # noqa: E402

FUZZ = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

SEEDS = [
    app_image(),
    app_image("esp32c6", hash_appended=False),
    partition_table(list(DEFAULT_LAYOUT))[:256],
    otadata((otadata_entry(1, 2), otadata_entry(2, 1))),
    build_nvs(ROWS, 0x6000)[:0x3000],
    build_spiffs([("/k.pem", b"-----BEGIN PRIVATE KEY-----\nAA==\n"), ("/a", b"x" * 600)], 0x2000),
]


@FUZZ
@given(st.binary(max_size=10_000))
def test_random_bytes(data: bytes) -> None:
    run_all_parsers(data)


@FUZZ
@given(st.sampled_from([b"\xe9", b"\xaa\x50", b"\xeb\xeb"]), st.binary(max_size=4096))
def test_magic_prefixed_bytes(prefix: bytes, data: bytes) -> None:
    run_all_parsers(prefix + data)


@FUZZ
@given(
    st.sampled_from(SEEDS),
    st.lists(st.tuples(st.integers(0, 1 << 20), st.integers(0, 255)), max_size=16),
    st.integers(0, 1 << 20),
)
def test_mutated_and_truncated_fixtures(
    seed: bytes, edits: list[tuple[int, int]], cut: int
) -> None:
    buf = bytearray(seed)
    for pos, val in edits:
        buf[pos % len(buf)] = val
    run_all_parsers(bytes(buf[: cut % (len(buf) + 1)]))


DUMP = default_dump()


@settings(max_examples=50, deadline=None)
@given(
    st.lists(st.tuples(st.integers(0, len(DUMP) - 1), st.integers(0, 255)), max_size=32),
    st.integers(0, len(DUMP)),
)
def test_mutated_full_dump(edits: list[tuple[int, int]], cut: int) -> None:
    buf = bytearray(DUMP)
    # concentrate edits on the structured regions (bootloader, table, otadata, app headers)
    hot = [0x1000, 0x8000, 0xD000, 0x10000, 0x190000]
    for i, (pos, val) in enumerate(edits):
        target = hot[i % len(hot)] + pos % 0x400 if i % 2 else pos
        buf[target] = val
    run_all_parsers(bytes(buf[:cut]))
