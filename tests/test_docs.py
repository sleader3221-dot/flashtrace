"""Generated documentation must be current (run ``python -m tools.gen_docs``)."""

from __future__ import annotations

import json

from tools.gen_docs import BENCH_JSON, README, RULES_MD, readme_with_bench, rules_markdown


def test_rules_md_is_current() -> None:
    assert RULES_MD.read_text(encoding="utf-8") == rules_markdown()


def test_readme_bench_table_is_current() -> None:
    text = README.read_text(encoding="utf-8")
    assert text == readme_with_bench(text, json.loads(BENCH_JSON.read_text()))
    assert "**PASS**" in text


def test_examples_are_reports_only() -> None:
    examples = BENCH_JSON.parent
    assert not list(examples.rglob("*.bin"))
    assert all(p.stat().st_size < 1_000_000 for p in examples.rglob("*") if p.is_file())
