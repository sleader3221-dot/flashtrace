from __future__ import annotations

import json
from pathlib import Path

import pytest

from flashtrace.commands import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, fallback_main
from tests.conftest import require_module
from tests.fixtures.generator import clean_dump
from tools.corpus.generate import generate


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("cli_corpus")
    generate(out, use_esptool=False)
    return out


def test_fallback_analyze_exit_codes(corpus: Path, tmp_path: Path) -> None:
    out = tmp_path / "r"
    dump = corpus / "pem_private_key_in_spiffs" / "dump.bin"
    fmts = ["--format", "json", "--format", "md", "--format", "html"]
    code = fallback_main(["analyze", str(dump), "--out", str(out), *fmts])
    assert code == EXIT_FINDINGS
    assert {p.name for p in out.iterdir()} == {
        "report.json",
        "report.md",
        "report.html",
        "evidence.sqlite",
    }
    data = json.loads((out / "report.json").read_text())
    assert "SEC.PRIVATE_KEY" in data["summary"]["rules_fired"]
    clean = tmp_path / "clean.bin"
    clean.write_bytes(clean_dump())
    assert fallback_main(["analyze", str(clean), "--out", str(tmp_path / "c")]) == EXIT_OK
    assert fallback_main(["analyze", str(tmp_path / "missing.bin")]) == EXIT_ERROR


def test_fallback_diff_and_bench(corpus: Path, tmp_path: Path) -> None:
    a = corpus / "clean_control" / "dump.bin"
    b = corpus / "pending_verify_ota" / "dump.bin"
    assert fallback_main(["diff", str(a), str(b), "--out", str(tmp_path / "d")]) == EXIT_OK
    assert (tmp_path / "d" / "diff.json").is_file() and (tmp_path / "d" / "diff.html").is_file()
    res = tmp_path / "bench_results.json"
    assert fallback_main(["bench", str(corpus), "--out", str(res)]) == EXIT_OK
    assert json.loads(res.read_text())["gate"]["passed"] is True
    assert res.with_suffix(".md").is_file()


def test_typer_cli(corpus: Path, tmp_path: Path) -> None:
    require_module("typer")
    from typer.testing import CliRunner

    from flashtrace.cli import app

    runner = CliRunner()
    r = runner.invoke(
        app,
        [
            "analyze",
            str(corpus / "wifi_creds_in_nvs" / "dump.bin"),
            "--out",
            str(tmp_path / "w"),
            "--format",
            "html",
        ],
    )
    assert r.exit_code == EXIT_FINDINGS, r.output
    assert (tmp_path / "w" / "report.html").is_file()
    r = runner.invoke(app, ["bench", str(corpus), "--out", str(tmp_path / "b.json")])
    assert r.exit_code == EXIT_OK, r.output
    r = runner.invoke(
        app,
        [
            "diff",
            str(corpus / "clean_control" / "dump.bin"),
            str(corpus / "forced_rollback" / "dump.bin"),
            "--out",
            str(tmp_path / "d"),
        ],
    )
    assert r.exit_code == EXIT_OK, r.output
    r = runner.invoke(app, ["analyze", str(tmp_path / "nope.bin")])
    assert r.exit_code == EXIT_ERROR
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and r.output.strip()
