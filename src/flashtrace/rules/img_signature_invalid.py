from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "IMG.SIGNATURE_INVALID"


@rule(
    RULE_ID,
    "high",
    "App image not signed by the supplied Secure Boot key",
    "With --sb-pubkey, every app image must carry a Secure Boot V2 signature block that"
    " verifies (CRC, image digest and RSA-PSS/ECDSA signature) against the supplied key."
    " Fires for unsigned images, tampered images and images signed by another key.",
    "Inactive without --sb-pubkey. An image legitimately signed with a second (revoked or"
    " rotated) key also fires; supply the key that should be trusted.",
    category="integrity",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    if not ctx.sb_key_supplied:
        return []
    out: list[Finding] = []
    for label, img in ctx.apps.items():
        if not img.image_length:
            continue
        checks = ctx.signature_checks.get(label, [])
        if any(c.verified for c in checks):
            continue
        if checks:
            ev = tuple(ctx.ev(c.offset, 1216, label) for c in checks)
            reasons = [f"block {c.block}: {c.reason}" for c in checks]
        else:
            sector = img.offset + -(-img.image_length // 4096) * 4096
            ev = (ctx.ev(sector, 4, label),)
            reasons = ["no signature block"]
        out.append(
            make_finding(
                RULE_ID,
                severity="high",
                title=f"{label}: not signed by the supplied key ({'; '.join(reasons)})",
                detail={"partition": label, "reasons": reasons},
                evidence=ev,
                confidence=0.95,
            )
        )
    return out
