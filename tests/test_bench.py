from __future__ import annotations

import json
from pathlib import Path

import pytest

from flashtrace.bench import RuleScore, markdown_table, run_bench
from tools.corpus.generate import devices, generate, internal_merge


@pytest.fixture(scope="module")
def corpus(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("corpus")
    generate(out, use_esptool=False)
    return out


def test_corpus_is_complete_and_deterministic(corpus: Path, tmp_path: Path) -> None:
    names = sorted(p.name for p in corpus.iterdir())
    assert names == sorted(d.name for d in devices()) and len(names) == 10
    generate(tmp_path, use_esptool=False)
    for n in names:
        assert (corpus / n / "dump.bin").read_bytes() == (tmp_path / n / "dump.bin").read_bytes()
        gt = json.loads((corpus / n / "ground_truth.json").read_text())
        assert gt["must_fire"] and set(gt["must_fire"]).isdisjoint(gt["must_not_fire"])
        assert len((corpus / n / "dump.bin").read_bytes()) == 4 * 1024 * 1024


def test_bench_passes_gate(corpus: Path) -> None:
    res = run_bench(corpus)
    assert res.passed, res.violations
    o = res.overall
    assert o.recall is not None and o.recall >= 0.95 and o.fp == 0
    md = markdown_table(res.as_dict())
    assert "**PASS**" in md and "| `NVS.DELETED_SECRET` |" in md


def test_gate_fails_on_forbidden_and_missed(corpus: Path, tmp_path: Path) -> None:
    import shutil

    bad = tmp_path / "bad"
    shutil.copytree(corpus / "clean_control", bad / "clean_control")
    gt_path = bad / "clean_control" / "ground_truth.json"
    gt = json.loads(gt_path.read_text())
    gt["must_fire"].append("NVS.WIFI_CREDENTIALS")  # will be missed
    gt["must_fire"].remove("SEC.NO_FLASH_ENCRYPTION")
    gt["must_not_fire"].append("SEC.NO_FLASH_ENCRYPTION")  # fires -> forbidden + unexpected
    gt_path.write_text(json.dumps(gt))
    res = run_bench(bad)
    assert not res.passed
    text = "\n".join(res.violations)
    assert "recall" in text and "forbidden SEC.NO_FLASH_ENCRYPTION" in text
    assert "unexpected medium finding SEC.NO_FLASH_ENCRYPTION" in text
    empty = tmp_path / "empty"
    empty.mkdir()
    assert not run_bench(empty).passed


def test_rule_score_math() -> None:
    s = RuleScore(tp=3, fp=1, fn=1)
    assert s.precision == 0.75 and s.recall == 0.75 and s.f1 == pytest.approx(0.75)
    assert RuleScore().as_dict()["precision"] is None


def test_internal_merge_layout() -> None:
    m = internal_merge({0x10: b"ab", 0x0: b"x"}, size=0x20)
    assert m[:1] == b"x" and m[0x10:0x12] == b"ab" and m[0x12:] == b"\xff" * 14
