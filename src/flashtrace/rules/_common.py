"""Shared helpers for secret-scanning rules."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

from flashtrace.context import AnalysisContext, ScanRegion
from flashtrace.model import Evidence, Finding, Severity, make_finding, sha256_hex
from flashtrace.redact import redact
from flashtrace.secrets import SecretMatch

Detector = Callable[[bytes], Iterator[SecretMatch]]


def region_matches(
    ctx: AnalysisContext, detector: Detector, regions: Iterable[ScanRegion] | None = None
) -> Iterator[tuple[ScanRegion, SecretMatch, tuple[Evidence, ...]]]:
    for region in ctx.scan_regions() if regions is None else regions:
        for m in detector(region.data):
            ev = region.evidence(ctx.dump, m.rel, m.length)
            if ev:
                yield region, m, ev


def secret_finding(
    ctx: AnalysisContext,
    rule_id: str,
    severity: Severity,
    title: str,
    region: ScanRegion,
    match: SecretMatch,
    evidence: tuple[Evidence, ...],
    *,
    is_secret: bool = True,
    confidence: float = 0.9,
    attck: tuple[str, ...] = (),
) -> Finding:
    shown = (
        redact(match.value, ctx.reveal_secrets)
        if is_secret
        else match.value.decode("utf-8", errors="backslashreplace")
    )
    detail = {
        "kind": match.kind,
        "region": region.label,
        "source": region.source,
        "value": shown,
        "redacted": is_secret and not ctx.reveal_secrets,
        "value_sha256": sha256_hex(match.value),
        "value_length": len(match.value),
    }
    if match.context:
        detail["context"] = match.context
    return make_finding(
        rule_id,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence,
        attck=attck,
        confidence=confidence * (0.5 if ctx.encryption_likely else 1.0),
    )


# Parser anomaly kinds owned by dedicated rules (everything else -> PARSE.ANOMALY).
OWNED_ANOMALIES: dict[str, str] = {
    "PT_MD5_MISMATCH": "PT.MD5_MISMATCH",
    "PT_OVERLAP": "PT.OVERLAP",
    "PT_OUT_OF_BOUNDS": "PT.OUT_OF_BOUNDS",
    "IMG_CHECKSUM_BAD": "IMG.CHECKSUM_BAD",
    "IMG_SHA256_BAD": "IMG.SHA256_BAD",
}


def anomaly_rule(
    ctx: AnalysisContext, kind: str, rule_id: str, severity: Severity, title: str
) -> list[Finding]:
    out: list[Finding] = []
    for partition, a in ctx.anomalies:
        if a.kind != kind:
            continue
        out.append(
            make_finding(
                rule_id,
                severity=severity,
                title=f"{title}: {a.message}",
                detail={"kind": a.kind, "partition": partition, **a.detail},
                evidence=(ctx.ev(a.offset, a.length, partition),),
                confidence=0.5 if ctx.encryption_likely else 1.0,
            )
        )
    return out
