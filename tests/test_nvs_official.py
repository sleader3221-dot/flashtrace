"""Cross-check against esp-idf-nvs-partition-gen 0.2.0 (runs in CI)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.conftest import require_module
from tests.fixtures.nvs_cases import EXPECTED, ROWS, SIZE, parse, values
from tools.corpus.nvs_writer import build_nvs, to_csv

require_module("esp_idf_nvs_partition_gen")


def official(rows: list[tuple[str, str, str, str]], size: int, tmp: Path) -> bytes:
    csv = tmp / "in.csv"
    out = tmp / "out.bin"
    csv.write_text(to_csv(rows))
    cmd = [sys.executable, "-m", "esp_idf_nvs_partition_gen", "generate"]
    proc = subprocess.run(
        [*cmd, str(csv), str(out), hex(size)],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp,
        timeout=120,
    )
    assert proc.returncode == 0 and out.exists(), proc.stdout + proc.stderr
    return out.read_bytes()


def test_writer_is_byte_identical_to_official_tool(tmp_path: Path) -> None:
    ref = official(ROWS, SIZE, tmp_path)
    assert build_nvs(ROWS, SIZE) == ref


def test_parser_recovers_official_tool_output(tmp_path: Path) -> None:
    got = values(parse(official(ROWS, SIZE, tmp_path)))
    for k, v in EXPECTED.items():
        assert got[k] == v, k


def test_many_small_entries_span_pages(tmp_path: Path) -> None:
    rows = [("ns", "namespace", "", "")] + [
        (f"k{i}", "data", "string" if i % 3 else "u32", f"value-{i}" if i % 3 else str(i))
        for i in range(300)
    ]
    ref = official(rows, 0x8000, tmp_path)
    assert build_nvs(rows, 0x8000) == ref
    got = values(parse(ref))
    assert got[("ns", "k299")] == "value-299" and got[("ns", "k0")] == 0
