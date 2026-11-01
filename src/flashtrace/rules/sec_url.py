from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import region_matches, secret_finding
from flashtrace.secrets import find_urls

RULE_ID = "SEC.URL"


@rule(
    RULE_ID,
    "info",
    "URL in flash",
    "An http:// or https:// URL is present (update servers, APIs, telemetry endpoints).",
    "Documentation/vendor URLs are common; this is an informational indicator, deduplicated "
    "by value.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    seen: set[bytes] = set()
    for region, m, ev in region_matches(ctx, find_urls):
        if True and m.value in seen:
            continue
        seen.add(m.value)
        out.append(
            secret_finding(
                ctx, RULE_ID, "info", f"URL in {region.label}", region, m, ev, is_secret=False
            )
        )
    return out
