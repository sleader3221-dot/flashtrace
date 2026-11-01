from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import anomaly_rule

RULE_ID = "IMG.SHA256_BAD"


@rule(
    RULE_ID,
    "high",
    "App image SHA-256 invalid",
    "The appended SHA-256 does not match the image bytes: the image was modified after build "
    "or is corrupted.",
    "Partially written OTA slots (interrupted update) also fail.",
    category="integrity",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    return anomaly_rule(ctx, "IMG_SHA256_BAD", RULE_ID, "high", "App image SHA-256 invalid")
