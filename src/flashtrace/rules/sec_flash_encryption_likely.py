from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.partition import DEFAULT_TABLE_OFFSET
from flashtrace.rules import rule

RULE_ID = "SEC.FLASH_ENCRYPTION_LIKELY"


@rule(
    RULE_ID,
    "info",
    "Flash encryption likely enabled",
    "No partition table magic at the expected offset and the region's Shannon entropy exceeds"
    " 7.5 bits/byte: the dump is most likely ciphertext, so FlashTrace skips structural parsing.",
    "Random/garbage dumps (bad read, wrong offset) look the same.",
    category="posture",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    dec = ctx.decryption
    if dec is not None and dec.flash_decrypted:
        return [
            make_finding(
                RULE_ID,
                severity="info",
                title=f"Flash encryption enabled ({dec.flash_scheme}); analysed with supplied key",
                detail={
                    "confirmed": True,
                    "scheme": dec.flash_scheme,
                    "decrypted_regions": [w for w, _o, _n in dec.flash_regions],
                    "original_sha256": dec.original_sha256,
                },
                evidence=(ctx.ev(ctx.table_offset or DEFAULT_TABLE_OFFSET, 0xC00, None),),
                confidence=1.0,
            )
        ]
    if not ctx.encryption_likely:
        return []
    return [
        make_finding(
            RULE_ID,
            severity="info",
            title="Flash encryption likely enabled; structural parsing skipped",
            detail={"reason": ctx.encryption_reason},
            evidence=(ctx.ev(DEFAULT_TABLE_OFFSET, 0x1000, None),),
            confidence=0.8,
        )
    ]
