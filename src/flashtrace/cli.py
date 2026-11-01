"""typer CLI (CLAUDE.md "CLI (target)"). Logic lives in :mod:`flashtrace.commands`."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from flashtrace import __version__
from flashtrace.commands import CHIPS, FORMATS, cmd_analyze, cmd_bench, cmd_diff

app = typer.Typer(
    name="flashtrace",
    help="Forensic triage for ESP32-family SPI flash dumps.",
    no_args_is_help=True,
    add_completion=False,
)


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(0)


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """FlashTrace."""


@app.command()
def analyze(
    dump: Annotated[Path, typer.Argument(help="Raw SPI flash dump (.bin).")],
    chip: Annotated[str, typer.Option(help=f"One of: {', '.join(CHIPS)}.")] = "auto",
    baseline: Annotated[
        list[Path] | None, typer.Option("--baseline", help="Known-good app image (repeatable).")
    ] = None,
    out: Annotated[Path | None, typer.Option("--out", help="Report directory.")] = None,
    fmt: Annotated[
        list[str] | None,
        typer.Option("--format", help=f"Report format, repeatable: {', '.join(FORMATS)}."),
    ] = None,
    reveal_secrets: Annotated[
        bool, typer.Option("--reveal-secrets", help="Show secret values unredacted.")
    ] = False,
) -> None:
    """Analyse one dump and write evidence-linked reports."""
    raise typer.Exit(
        cmd_analyze(
            dump,
            chip=chip,
            baselines=baseline or [],
            out=out,
            formats=fmt or ["json"],
            reveal_secrets=reveal_secrets,
        )
    )


@app.command()
def diff(
    dump_a: Annotated[Path, typer.Argument(help="Earlier dump.")],
    dump_b: Annotated[Path, typer.Argument(help="Later dump.")],
    out: Annotated[Path, typer.Option("--out", help="Output directory.")],
) -> None:
    """Compare two dumps partition by partition (DIFF.* findings)."""
    raise typer.Exit(cmd_diff(dump_a, dump_b, out=out))


@app.command()
def bench(
    corpus: Annotated[Path, typer.Argument(help="Corpus directory with ground_truth.json files.")],
    out: Annotated[Path, typer.Option("--out", help="Results JSON path.")] = Path(
        "bench_results.json"
    ),
) -> None:
    """Score every rule against a ground-truth corpus and apply the CI gate."""
    raise typer.Exit(cmd_bench(corpus, out=out))


def run() -> None:
    app()
