from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "OTA.PENDING_VERIFY"


@rule(
    RULE_ID,
    "low",
    "Active OTA image awaiting verification",
    "The selected otadata entry is in ESP_OTA_IMG_PENDING_VERIFY: a new image booted but was"
    " never marked valid; with rollback enabled the next reboot marks it ABORTED.",
    "Captured mid-update on a healthy device; usually transient.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    if ctx.otadata is None or ctx.otadata.active is None:
        return []
    e = ctx.otadata.active
    if e.state_name != "PENDING_VERIFY":
        return []
    return [
        make_finding(
            RULE_ID,
            severity="low",
            title=f"Active OTA slot {ctx.active_slot_label() or '?'} is PENDING_VERIFY",
            detail={"seq": e.seq, "slot": ctx.active_slot_label(), "state": e.state_name},
            evidence=(ctx.ev(e.offset, 32, None),),
        )
    ]
