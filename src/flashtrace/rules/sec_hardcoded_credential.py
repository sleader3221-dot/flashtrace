from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import region_matches, secret_finding
from flashtrace.secrets import find_credentials

RULE_ID = "SEC.HARDCODED_CREDENTIAL"


@rule(
    RULE_ID,
    "high",
    "Hardcoded credential in flash",
    'A password/secret/token assignment (e.g. password=..., "pwd": ...) or URL userinfo '
    "(scheme://user:pass@) is embedded.",
    "Placeholder values (changeme, %s, password, ****) and format strings are ignored.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    seen: set[bytes] = set()
    for region, m, ev in region_matches(ctx, find_credentials):
        if True and m.value in seen:
            continue
        seen.add(m.value)
        out.append(
            secret_finding(
                ctx,
                RULE_ID,
                "high",
                f"Hardcoded credential ({m.context}) in {region.label}",
                region,
                m,
                ev,
                is_secret=True,
            )
        )
    return out
