from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import anomaly_rule

RULE_ID = "PT.MD5_MISMATCH"


@rule(
    RULE_ID,
    "high",
    "Partition table MD5 mismatch",
    "The MD5 entry of the partition table does not match the entries before it: the table was"
    " edited after it was generated.",
    "Some very old ESP-IDF tables have no MD5 entry; absence is not reported, only mismatch.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    return anomaly_rule(ctx, "PT_MD5_MISMATCH", RULE_ID, "high", "Partition table MD5 mismatch")
