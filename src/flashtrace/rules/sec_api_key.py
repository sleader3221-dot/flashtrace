from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import region_matches, secret_finding
from flashtrace.secrets import find_aws_keys, find_generic_tokens

RULE_ID = "SEC.API_KEY"


@rule(
    RULE_ID,
    "high",
    "API key or access token in flash",
    "An AWS access key ID (AKIA/ASIA + 16 chars) or a generic token (>= 32 base64/url-safe"
    " characters mixing upper, lower and digits with >= 4.0 bits/char entropy) is present.",
    "Generic tokens can match random-looking identifiers; pure-hex strings (hashes) are"
    " excluded. AWS key IDs are reported with higher confidence.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    seen: set[bytes] = set()
    for detector, conf, what in (
        (find_aws_keys, 0.95, "AWS access key ID"),
        (find_generic_tokens, 0.6, "High-entropy token"),
    ):
        for region, m, ev in region_matches(ctx, detector):
            if m.value in seen:
                continue
            seen.add(m.value)
            out.append(
                secret_finding(
                    ctx,
                    RULE_ID,
                    "high",
                    f"{what} in {region.label}",
                    region,
                    m,
                    ev,
                    confidence=conf,
                )
            )
    return out
