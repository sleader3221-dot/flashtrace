from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "IMG.NO_APP_DESC"


@rule(
    RULE_ID,
    "medium",
    "App image without esp_app_desc_t",
    "An app partition holds a parseable image but no esp_app_desc_t (magic 0xABCD5432) at the"
    " start of any segment: not built by the ESP-IDF app build, or the descriptor was stripped.",
    "Non-ESP-IDF toolchains (bare-metal, some Arduino/Rust builds) may legitimately omit it.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    for label, img in ctx.apps.items():
        if img.app_desc is not None or img.header is None:
            continue
        out.append(
            make_finding(
                RULE_ID,
                severity="medium",
                title=f"No esp_app_desc_t in {label}",
                detail={"partition": label, "segments": len(img.segments)},
                evidence=(ctx.ev(img.offset, 24, label),),
                confidence=0.9,
            )
        )
    return out
