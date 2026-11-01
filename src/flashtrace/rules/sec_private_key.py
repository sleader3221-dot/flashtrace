from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import region_matches, secret_finding
from flashtrace.secrets import find_private_keys

RULE_ID = "SEC.PRIVATE_KEY"


@rule(
    RULE_ID,
    "critical",
    "PEM private key in flash",
    "A PEM-armoured private key block (RSA/EC/DSA/OpenSSH/PKCS#8, incl. ENCRYPTED) is present"
    " in an app image, NVS value or filesystem file.",
    "Test vectors and example keys compiled into firmware still fire; the key is exposed "
    "either way.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    seen: set[bytes] = set()
    for region, m, ev in region_matches(ctx, find_private_keys):
        seen.add(m.value)
        out.append(
            secret_finding(
                ctx,
                RULE_ID,
                "critical",
                f"Private key ({m.context}) in {region.label}",
                region,
                m,
                ev,
                is_secret=True,
            )
        )
    return out
