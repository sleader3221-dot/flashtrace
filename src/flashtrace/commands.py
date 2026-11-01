"""Command implementations shared by the typer CLI and the argparse fallback.

Exit codes: 0 = no high/critical findings, 1 = high/critical present, 2 = tool error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from flashtrace import __version__
from flashtrace.bench import markdown_table, run_bench
from flashtrace.diff import diff_dumps
from flashtrace.io import DumpTooLargeError, load_dump
from flashtrace.pipeline import analyze, load_baselines, write_store
from flashtrace.report import html, json_report, markdown
from flashtrace.report.model import diff_dict, result_dict

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
CHIPS = ("auto", "esp32", "esp32s2", "esp32s3", "esp32c3", "esp32c6")
FORMATS = ("json", "html", "md")

Renderer = Callable[[dict[str, Any]], str]


def _renderers() -> dict[str, Renderer]:
    return {"json": json_report.dumps, "md": markdown.render, "html": html.render}


def _err(msg: str) -> int:
    print(f"flashtrace: error: {msg}", file=sys.stderr)
    return EXIT_ERROR


def write_reports(data: dict[str, Any], out: Path, formats: Sequence[str], stem: str) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    renderers = _renderers()
    paths: list[Path] = []
    for fmt in formats:
        if fmt not in renderers:
            raise ValueError(f"unsupported format {fmt!r}")
        ext = {"json": "json", "md": "md", "html": "html"}[fmt]
        p = out / f"{stem}.{ext}"
        p.write_text(renderers[fmt](data), encoding="utf-8")
        paths.append(p)
    return paths


def cmd_analyze(
    dump: Path,
    *,
    chip: str = "auto",
    baselines: Sequence[Path] = (),
    out: Path | None = None,
    formats: Sequence[str] = ("json",),
    reveal_secrets: bool = False,
) -> int:
    if chip not in CHIPS:
        return _err(f"--chip must be one of {', '.join(CHIPS)}")
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        return _err(f"unsupported --format {bad}")
    try:
        data = load_dump(dump)
        base = load_baselines(baselines)
    except (OSError, DumpTooLargeError) as exc:
        return _err(str(exc))
    result = analyze(data, reveal_secrets=reveal_secrets, baselines=base, chip=chip)
    out_dir = out or Path("flashtrace_report")
    report = result_dict(result)
    try:
        written = write_reports(report, out_dir, formats, "report")
        write_store(result, out_dir / "evidence.sqlite")
    except OSError as exc:
        return _err(str(exc))
    counts = result.severity_counts()
    print(
        f"{dump}: {len(result.findings)} findings "
        + " ".join(f"{k}={v}" for k, v in counts.items() if v)
        + f" -> {', '.join(str(p) for p in written)}"
    )
    if result.rule_errors:
        for e in result.rule_errors:
            print(f"flashtrace: rule error: {e}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_FINDINGS if result.has_high() else EXIT_OK


def cmd_diff(
    dump_a: Path,
    dump_b: Path,
    *,
    out: Path,
    formats: Sequence[str] = ("json", "html", "md"),
    reveal_secrets: bool = False,
) -> int:
    try:
        a, b = load_dump(dump_a), load_dump(dump_b)
    except (OSError, DumpTooLargeError) as exc:
        return _err(str(exc))
    res = diff_dumps(a, b, reveal_secrets)
    data = diff_dict(res)
    try:
        written = write_reports(data, out, formats, "diff")
    except OSError as exc:
        return _err(str(exc))
    print(f"{len(res.findings)} differences -> {', '.join(str(p) for p in written)}")
    return EXIT_FINDINGS if res.has_high() else EXIT_OK


def cmd_bench(corpus: Path, *, out: Path) -> int:
    if not corpus.is_dir():
        return _err(f"corpus directory {corpus} does not exist")
    res = run_bench(corpus)
    data = res.as_dict()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        out.with_suffix(".md").write_text(markdown_table(data), encoding="utf-8")
    except OSError as exc:
        return _err(str(exc))
    print(markdown_table(data))
    return EXIT_OK if res.passed else EXIT_FINDINGS


def fallback_main(argv: Sequence[str] | None = None) -> int:
    """argparse front-end with the same commands, for environments without typer."""
    p = argparse.ArgumentParser(prog="flashtrace")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("dump", type=Path)
    a.add_argument("--chip", default="auto", choices=CHIPS)
    a.add_argument("--baseline", action="append", type=Path, default=[])
    a.add_argument("--out", type=Path, default=None)
    a.add_argument("--format", action="append", choices=FORMATS, default=None)
    a.add_argument("--reveal-secrets", action="store_true")
    d = sub.add_parser("diff")
    d.add_argument("dump_a", type=Path)
    d.add_argument("dump_b", type=Path)
    d.add_argument("--out", type=Path, required=True)
    b = sub.add_parser("bench")
    b.add_argument("corpus", type=Path)
    b.add_argument("--out", type=Path, default=Path("bench_results.json"))
    ns = p.parse_args(argv)
    if ns.cmd == "analyze":
        return cmd_analyze(
            ns.dump,
            chip=ns.chip,
            baselines=ns.baseline,
            out=ns.out,
            formats=ns.format or ["json"],
            reveal_secrets=ns.reveal_secrets,
        )
    if ns.cmd == "diff":
        return cmd_diff(ns.dump_a, ns.dump_b, out=ns.out)
    return cmd_bench(ns.corpus, out=ns.out)
