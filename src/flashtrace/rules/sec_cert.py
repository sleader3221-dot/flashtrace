from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import region_matches, secret_finding
from flashtrace.secrets import find_certificates

RULE_ID = "SEC.CERT"


@rule(
    RULE_ID,
    "info",
    "X.509 certificate in flash",
    "A PEM certificate, or a DER certificate (ASN.1 SEQUENCE header that parses with "
    "cryptography), is present.",
    "CA bundles legitimately contain many certificates; each distinct certificate is reported"
    " once.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    seen: set[bytes] = set()
    for region, m, ev in region_matches(ctx, find_certificates):
        if True and m.value in seen:
            continue
        seen.add(m.value)
        out.append(
            secret_finding(
                ctx,
                RULE_ID,
                "info",
                f"Certificate in {region.label}: {m.context}",
                region,
                m,
                ev,
                is_secret=False,
            )
        )
    return out
