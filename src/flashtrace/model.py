"""Core data model: Evidence, Finding and parser Anomaly records.

Every finding cites evidence: absolute dump offset, length, partition label and
the SHA-256 of exactly those bytes. ``make_evidence`` is the only sanctioned way
to build an :class:`Evidence` from a dump so the hash always matches the bytes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")

ByteSource = bytes | bytearray | memoryview

ANOMALY_RULE_ID = "PARSE.ANOMALY"


@dataclass(frozen=True)
class Evidence:
    partition: str | None
    offset: int  # absolute offset in dump
    length: int
    sha256: str  # of dump[offset:offset+length]


@dataclass(frozen=True)
class Finding:
    id: str  # stable: rule_id + evidence hash prefix
    rule_id: str  # e.g. "NVS.WIFI_CREDENTIALS"
    severity: Severity
    title: str
    detail: Mapping[str, Any]  # structured, secrets redacted unless revealed
    evidence: tuple[Evidence, ...]
    attck: tuple[str, ...] = ()
    confidence: float = 1.0


@dataclass(frozen=True)
class Anomaly:
    """A structural problem a parser hit instead of crashing.

    ``offset``/``length`` are absolute dump coordinates of the offending bytes,
    clamped by the parser to the data it was given (``length`` may be 0 when the
    problem is that bytes are *missing*, e.g. truncation).
    """

    kind: str  # short machine-readable code, e.g. "TRUNCATED", "BAD_MAGIC"
    message: str
    offset: int
    length: int
    detail: Mapping[str, Any] = field(default_factory=dict)


def sha256_hex(data: ByteSource) -> str:
    return hashlib.sha256(data).hexdigest()


def make_evidence(dump: ByteSource, offset: int, length: int, partition: str | None) -> Evidence:
    """Build Evidence for ``dump[offset:offset+length]``, clamped to the dump."""
    size = len(dump)
    start = min(max(offset, 0), size)
    end = min(max(start + max(length, 0), start), size)
    return Evidence(
        partition=partition,
        offset=start,
        length=end - start,
        sha256=sha256_hex(memoryview(dump)[start:end]),
    )


def finding_id(rule_id: str, evidence: tuple[Evidence, ...]) -> str:
    """Stable id: rule id + prefix of a hash over the evidence coordinates and hashes."""
    h = hashlib.sha256(rule_id.encode())
    for ev in evidence:
        h.update(f"|{ev.partition}|{ev.offset}|{ev.length}|{ev.sha256}".encode())
    return f"{rule_id}:{h.hexdigest()[:16]}"


def make_finding(
    rule_id: str,
    *,
    severity: Severity,
    title: str,
    detail: Mapping[str, Any],
    evidence: tuple[Evidence, ...],
    attck: tuple[str, ...] = (),
    confidence: float = 1.0,
) -> Finding:
    if not evidence:
        raise ValueError("a Finding must cite at least one piece of Evidence")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be within [0, 1]")
    return Finding(
        id=finding_id(rule_id, evidence),
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=dict(detail),
        evidence=evidence,
        attck=attck,
        confidence=confidence,
    )


def anomaly_finding(dump: ByteSource, anomaly: Anomaly, partition: str | None) -> Finding:
    """Convert a parser :class:`Anomaly` into an ``anomaly`` Finding (CLAUDE.md rule 2)."""
    ev = make_evidence(dump, anomaly.offset, anomaly.length, partition)
    return make_finding(
        ANOMALY_RULE_ID,
        severity="low",
        title=anomaly.message,
        detail={"kind": anomaly.kind, **anomaly.detail},
        evidence=(ev,),
    )
