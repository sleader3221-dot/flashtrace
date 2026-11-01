from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import anomaly_rule

RULE_ID = "PT.OUT_OF_BOUNDS"


@rule(
    RULE_ID,
    "high",
    "Partition beyond end of dump",
    "A partition extends past the end of the dump: the table is inconsistent with the flash "
    "size, or the dump is truncated.",
    "A deliberately partial dump (e.g. only the first 2 MB read) also triggers this.",
    category="integrity",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    return anomaly_rule(ctx, "PT_OUT_OF_BOUNDS", RULE_ID, "high", "Partition beyond end of dump")
