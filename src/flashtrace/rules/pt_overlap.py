from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import anomaly_rule

RULE_ID = "PT.OVERLAP"


@rule(
    RULE_ID,
    "high",
    "Overlapping partitions",
    "Two non-empty partitions share flash addresses, which can hide data or let one partition"
    " overwrite another.",
    "Rare in legitimate builds; gen_esp32part.py refuses overlapping layouts.",
    category="integrity",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    return anomaly_rule(ctx, "PT_OVERLAP", RULE_ID, "high", "Overlapping partitions")
