from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.otadata import STATE_ABORTED, STATE_INVALID
from flashtrace.rules import rule

RULE_ID = "OTA.INVALID_ACTIVE"


@rule(
    RULE_ID,
    "high",
    "Selected or latest OTA image is invalid",
    "Either the otadata entry with the highest sequence (the latest OTA) is INVALID/ABORTED and"
    " the device fell back, or the slot the bootloader will select holds no image or one that"
    " fails its checksum / SHA-256.",
    "A legitimately rejected update (rollback working as designed) fires the first variant.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    o = ctx.otadata
    if o is None:
        return []
    out: list[Finding] = []
    written = [e for e in o.entries if e.crc_ok and not e.erased and e.seq != 0xFFFFFFFF]
    if written:
        latest = max(written, key=lambda e: e.seq)
        if latest.state in (STATE_INVALID, STATE_ABORTED):
            out.append(
                make_finding(
                    RULE_ID,
                    severity="high",
                    title=f"Latest OTA (seq {latest.seq}) is {latest.state_name}",
                    detail={"seq": latest.seq, "state": latest.state_name, "variant": "latest"},
                    evidence=(ctx.ev(latest.offset, 32, None),),
                )
            )
    label = ctx.active_slot_label()
    if label is not None and o.active is not None:
        img = ctx.apps.get(label)
        bad = img is None or img.checksum_valid is False or img.sha256_valid is False
        if bad:
            info = ctx.partitions.get(label)
            ev = [ctx.ev(o.active.offset, 32, None)]
            if info is not None:
                ev.append(ctx.ev(info.entry.offset, 24, label))
            out.append(
                make_finding(
                    RULE_ID,
                    severity="high",
                    title=f"Selected slot {label} has no valid image",
                    detail={
                        "slot": label,
                        "variant": "active_image",
                        "image_present": img is not None,
                        "checksum_valid": None if img is None else img.checksum_valid,
                        "sha256_valid": None if img is None else img.sha256_valid,
                    },
                    evidence=tuple(ev),
                )
            )
    return out
