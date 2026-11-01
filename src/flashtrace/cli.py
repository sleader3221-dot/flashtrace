"""typer CLI (CLAUDE.md "CLI (target)"). Logic lives in :mod:`flashtrace.commands`."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from flashtrace import __version__
from flashtrace.commands import CHIPS, FORMATS, cmd_analyze, cmd_bench, cmd_diff, cmd_explain
from flashtrace.explain import DEFAULT_MODEL

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
    flash_key: Annotated[
        Path | None,
        typer.Option("--flash-key", help="Flash-encryption key file (16/24/32/64 bytes)."),
    ] = None,
    flash_crypt_conf: Annotated[
        str, typer.Option("--flash-crypt-conf", help="ESP32 FLASH_CRYPT_CONFIG eFuse value.")
    ] = "0xF",
    nvs_key: Annotated[
        Path | None,
        typer.Option("--nvs-key", help="NVS encryption key (64 bytes or nvs_keys image)."),
    ] = None,
    sb_pubkey: Annotated[
        Path | None,
        typer.Option("--sb-pubkey", help="Secure Boot V2 public key (PEM/DER) to verify apps."),
    ] = None,
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
            flash_key=flash_key,
            flash_crypt_conf=int(flash_crypt_conf, 0),
            nvs_key=nvs_key,
            sb_pubkey=sb_pubkey,
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
def explain(
    report: Annotated[Path, typer.Argument(help="report.json written by analyze or diff.")],
    out: Annotated[Path, typer.Option("--out", help="Output directory.")],
    model: Annotated[str, typer.Option(help="Claude model ID.")] = DEFAULT_MODEL,
    allow_revealed: Annotated[
        bool, typer.Option("--allow-revealed", help="Allow sending an unredacted report.")
    ] = False,
) -> None:
    """Optional: plain-language explanation of existing findings (needs flashtrace[explain])."""
    raise typer.Exit(cmd_explain(report, out=out, model=model, allow_revealed=allow_revealed))


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
