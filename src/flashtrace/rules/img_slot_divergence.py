from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule
from flashtrace.rules._versions import semver

RULE_ID = "IMG.SLOT_DIVERGENCE"


@rule(
    RULE_ID,
    "medium",
    "OTA slots diverge",
    "Two OTA slots carry different project_name or idf_ver, or their versions are not"
    " monotonic with the OTA sequence (the most recently written slot has the lower semantic"
    " version) or jump by more than one major version.",
    "Legitimate product renames or IDF upgrades between releases also fire; review the pair.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    slots = [
        (s, lbl, img.app_desc)
        for s, lbl, img in ctx.ota_slots()
        if img is not None and img.app_desc is not None
    ]
    seq_by_slot: dict[int, int] = {}
    if ctx.otadata and ctx.otadata.num_ota_apps:
        for e in ctx.otadata.entries:
            if e.valid:
                seq_by_slot[(e.seq - 1) % ctx.otadata.num_ota_apps] = max(
                    e.seq, seq_by_slot.get((e.seq - 1) % ctx.otadata.num_ota_apps, 0)
                )
    out: list[Finding] = []
    for i, (sa, la, da) in enumerate(slots):
        for sb, lb, db in slots[i + 1 :]:
            reasons: list[str] = []
            if da.project_name != db.project_name:
                reasons.append(f"project_name {da.project_name!r} != {db.project_name!r}")
            if da.idf_ver != db.idf_ver:
                reasons.append(f"idf_ver {da.idf_ver!r} != {db.idf_ver!r}")
            va, vb = semver(da.version), semver(db.version)
            if va and vb:
                if abs(va[0] - vb[0]) > 1:
                    reasons.append(f"major version jump {da.version} -> {db.version}")
                qa, qb = seq_by_slot.get(sa), seq_by_slot.get(sb)
                if qa is not None and qb is not None and qa != qb:
                    newer, older = (va, vb) if qa > qb else (vb, va)
                    if newer < older:
                        reasons.append("newest OTA write carries the lower version")
            if not reasons:
                continue
            out.append(
                make_finding(
                    RULE_ID,
                    severity="medium",
                    title=f"{la} and {lb} diverge: " + "; ".join(reasons),
                    detail={
                        "slots": [la, lb],
                        "reasons": reasons,
                        la: {"project": da.project_name, "version": da.version, "idf": da.idf_ver},
                        lb: {"project": db.project_name, "version": db.version, "idf": db.idf_ver},
                    },
                    evidence=(ctx.ev(da.offset, 256, la), ctx.ev(db.offset, 256, lb)),
                    confidence=0.8,
                )
            )
    return out
