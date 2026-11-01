from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "SEC.NO_SECURE_BOOT"


@rule(
    RULE_ID,
    "medium",
    "No Secure Boot V2 signature on any app",
    "No app image has a Secure Boot V2 signature block (magic 0xE7, version 0x02/0x03) at the"
    " first 4 KB boundary after the image: images are unsigned (structural check only).",
    "Secure Boot V1 (ESP32 ECO<3) uses a different scheme and is not detected here.",
    category="posture",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    complete = {lbl: img for lbl, img in ctx.apps.items() if img.image_length}
    if not complete or any(img.signature_blocks for img in complete.values()):
        return []
    ev = []
    for lbl, img in complete.items():
        end = img.offset + (img.image_length or 0)
        sector = -(-end // 4096) * 4096
        ev.append(ctx.ev(sector, 2, lbl))
    return [
        make_finding(
            RULE_ID,
            severity="medium",
            title="App images carry no Secure Boot V2 signature block",
            detail={"apps": sorted(complete)},
            evidence=tuple(ev),
            confidence=0.85,
        )
    ]
