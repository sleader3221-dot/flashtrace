from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "SEC.NO_FLASH_ENCRYPTION"


@rule(
    RULE_ID,
    "medium",
    "Flash encryption not enabled",
    "The partition table and at least one app image parse as plaintext, so anyone with physical"
    " access can read firmware, NVS and filesystems.",
    "Fires on every plaintext dump by design (posture finding).",
    category="posture",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    if ctx.table is None or ctx.table_offset is None or not ctx.apps:
        return []
    if ctx.decryption is not None and ctx.decryption.flash_decrypted:
        return []  # contents were ciphertext; the supplied key decrypted them
    first = next(iter(ctx.apps.values()))
    return [
        make_finding(
            RULE_ID,
            severity="medium",
            title="Flash contents are plaintext (no flash encryption)",
            detail={"table_offset": ctx.table_offset, "apps_parsed": sorted(ctx.apps)},
            evidence=(
                ctx.ev(ctx.table_offset, max(ctx.table.length, 32), None),
                ctx.ev(first.offset, 24, next(iter(ctx.apps))),
            ),
        )
    ]
