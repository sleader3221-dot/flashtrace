from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "CORE.PRESENT"


@rule(
    RULE_ID,
    "medium",
    "Coredump present",
    "The coredump partition is not erased: the device crashed at least once and saved a core"
    " dump (task stacks/memory, possibly containing secrets).",
    "Crashes during development are common; still worth retrieving for analysis.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    c = ctx.coredump
    if c is None or not c.present:
        return []
    length = (
        min(c.data_len or 64, c.size) if c.data_len and c.data_len <= c.size else min(64, c.size)
    )
    return [
        make_finding(
            RULE_ID,
            severity="medium",
            title=f"Coredump present ({c.format})",
            detail={
                "partition": c.partition,
                "format": c.format,
                "size": c.size,
                "data_len": c.data_len,
                "version": None if c.version is None else f"{c.version:#010x}",
                "chip_id": c.chip_id,
                "tasks": c.tasks_num,
                "elf_offset": c.elf_offset,
            },
            evidence=(ctx.ev(c.offset, length, c.partition),),
        )
    ]
