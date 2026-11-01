from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import anomaly_rule

RULE_ID = "IMG.CHECKSUM_BAD"


@rule(
    RULE_ID,
    "high",
    "App image checksum invalid",
    "The XOR checksum (seed 0xEF) stored after the segments does not match the segment data: "
    "the image was modified or corrupted.",
    "Partially written OTA slots (interrupted update) also fail.",
    category="integrity",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    return anomaly_rule(ctx, "IMG_CHECKSUM_BAD", RULE_ID, "high", "App image checksum invalid")
