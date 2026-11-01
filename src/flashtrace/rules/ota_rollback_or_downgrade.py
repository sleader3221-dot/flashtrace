from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule
from flashtrace.rules._versions import semver

RULE_ID = "OTA.ROLLBACK_OR_DOWNGRADE"


@rule(
    RULE_ID,
    "high",
    "Active OTA slot is older than the inactive one",
    "The slot selected by otadata has a lower secure_version than another OTA slot, or a lower"
    " semantic version when both versions parse as semver: a rollback or forced downgrade.",
    "A deliberate, operator-approved rollback also fires; secure_version anti-rollback would"
    " normally prevent the secure_version case on devices with it enabled.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    active = ctx.active_slot_label()
    if active is None or ctx.otadata is None or ctx.otadata.active is None:
        return []
    img_a = ctx.apps.get(active)
    if img_a is None or img_a.app_desc is None:
        return []
    da = img_a.app_desc
    out: list[Finding] = []
    for _slot, label, img in ctx.ota_slots():
        if label == active or img is None or img.app_desc is None:
            continue
        db = img.app_desc
        reasons: list[str] = []
        if da.secure_version < db.secure_version:
            reasons.append(f"secure_version {da.secure_version} < {db.secure_version}")
        va, vb = semver(da.version), semver(db.version)
        if va and vb and va < vb:
            reasons.append(f"version {da.version} < {db.version}")
        if not reasons:
            continue
        out.append(
            make_finding(
                RULE_ID,
                severity="high",
                title=f"Active slot {active} is older than {label}: " + "; ".join(reasons),
                detail={
                    "active": active,
                    "other": label,
                    "reasons": reasons,
                    "active_version": da.version,
                    "other_version": db.version,
                    "active_secure_version": da.secure_version,
                    "other_secure_version": db.secure_version,
                },
                evidence=(
                    ctx.ev(ctx.otadata.active.offset, 32, None),
                    ctx.ev(da.offset, 256, active),
                    ctx.ev(db.offset, 256, label),
                ),
                confidence=0.9,
            )
        )
    return out
