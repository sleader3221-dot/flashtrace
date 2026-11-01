from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "IMG.UNKNOWN_BUILD"


@rule(
    RULE_ID,
    "high",
    "App image not in baseline set",
    "With --baseline images supplied, an app image whose SHA-256 (over the whole image incl."
    " checksum and appended digest) matches none of them. Inactive without baselines.",
    "Any legitimate build that was not added to the baseline set also fires.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.baselines:
        return []
    out: list[Finding] = []
    for label, img in ctx.apps.items():
        if not img.image_length:
            continue
        ev = ctx.ev(img.offset, img.image_length, label)
        if ev.sha256 in ctx.baselines:
            continue
        desc = img.app_desc
        out.append(
            make_finding(
                RULE_ID,
                severity="high",
                title=f"Unknown build in {label}"
                + (f" ({desc.project_name} {desc.version})" if desc else ""),
                detail={
                    "partition": label,
                    "image_sha256": ev.sha256,
                    "baseline_count": len(ctx.baselines),
                    "project_name": desc.project_name if desc else None,
                    "version": desc.version if desc else None,
                },
                evidence=(ev,),
                confidence=0.95,
            )
        )
    return out
