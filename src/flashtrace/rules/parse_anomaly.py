from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import ANOMALY_RULE_ID, Finding, anomaly_finding
from flashtrace.rules import rule
from flashtrace.rules._common import OWNED_ANOMALIES


@rule(
    ANOMALY_RULE_ID,
    "low",
    "Structural anomaly",
    "A parser met malformed or unexpected structure (truncation, bad magic, CRC mismatch, …)"
    " and recorded it instead of failing. Anomalies with a dedicated rule are excluded.",
    "Normal wear (e.g. a FREEING NVS page) can produce low-value anomalies.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    return [
        anomaly_finding(ctx.dump, a, partition)
        for partition, a in ctx.anomalies
        if a.kind not in OWNED_ANOMALIES
    ]
