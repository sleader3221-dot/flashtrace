"""End-to-end analysis: dump -> context -> rules -> findings, timeline, evidence store.

Rules come from the registry (``rules.load_rules``); nothing here names a rule.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flashtrace import __version__
from flashtrace.appimage import parse_app_image
from flashtrace.context import AnalysisContext, build_context
from flashtrace.evidence import EvidenceStore
from flashtrace.model import SEVERITIES, Anomaly, Evidence, Finding, sha256_hex
from flashtrace.nvs import NvsEntry
from flashtrace.rules import load_rules

SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# Device clocks before this are almost certainly unset (epoch 0 / 2000-01-01 RTC defaults)
TS_MIN = dt.datetime(2015, 1, 1, tzinfo=dt.UTC)
TS_MAX = dt.datetime(2040, 1, 1, tzinfo=dt.UTC)
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")
APP_DESC_TS_FMT = "%b %d %Y %H:%M:%S"  # __DATE__ " " __TIME__, e.g. "Jan  1 2026 12:00:00"


@dataclass(frozen=True)
class TimelineEntry:
    ts_source: str  # where the value came from (never a trusted wall clock)
    value: str  # raw device-reported value
    iso: str | None  # normalised UTC ISO-8601 when the value could be interpreted
    evidence: Evidence
    trust: str = "device-reported, untrusted"
    finding_id: str | None = None


@dataclass
class AnalysisResult:
    ctx: AnalysisContext
    findings: list[Finding]
    timeline: list[TimelineEntry]
    rule_errors: list[str] = field(default_factory=list)
    chip_requested: str = "auto"
    analysed_at: str = ""
    tool_version: str = __version__

    @property
    def chip(self) -> str | None:
        if self.chip_requested != "auto":
            return self.chip_requested
        return self.ctx.chip.chip if self.ctx.chip else None

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=SEVERITY_RANK.__getitem__)

    def has_high(self) -> bool:
        return any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"] for f in self.findings)


def baseline_hash(data: bytes) -> str:
    """SHA-256 used for --baseline matching: the app image bytes, else the whole file."""
    img = parse_app_image(data)
    if img is not None and img.image_length:
        return sha256_hex(data[: img.image_length])
    return sha256_hex(data)


def load_baselines(paths: Iterable[str | Path]) -> list[str]:
    return [baseline_hash(Path(p).read_bytes()) for p in paths]


def _sort_key(f: Finding) -> tuple[int, str, int, str]:
    first = f.evidence[0].offset if f.evidence else -1
    return (-SEVERITY_RANK[f.severity], f.rule_id, first, f.id)


def run_rules(ctx: AnalysisContext) -> tuple[list[Finding], list[str]]:
    findings: dict[str, Finding] = {}
    errors: list[str] = []
    for rule_id, r in load_rules().items():
        try:
            for f in r(ctx):
                findings.setdefault(f.id, f)
        except Exception as exc:  # a rule bug must not hide every other finding
            errors.append(f"{rule_id}: {type(exc).__name__}: {exc}")
    return sorted(findings.values(), key=_sort_key), errors


def _nvs_timestamp(e: NvsEntry) -> str | None:
    v = e.value
    if isinstance(v, int) and e.type_name in ("U32", "I32", "U64", "I64"):
        for scale in (1, 1000):
            try:
                t = dt.datetime.fromtimestamp(v / scale, tz=dt.UTC)
            except (OverflowError, OSError, ValueError):
                continue
            if TS_MIN <= t < TS_MAX:
                return t.isoformat()
        return None
    if isinstance(v, str) and ISO_RE.match(v.strip()):
        try:
            t = dt.datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        t = t if t.tzinfo else t.replace(tzinfo=dt.UTC)
        return t.astimezone(dt.UTC).isoformat()
    return None


def build_timeline(ctx: AnalysisContext) -> list[TimelineEntry]:
    out: list[TimelineEntry] = []
    for label, img in ctx.apps.items():
        d = img.app_desc
        if d is None or not (d.date or d.time):
            continue
        raw = f"{d.date} {d.time}".strip()
        iso: str | None
        try:
            iso = (
                dt.datetime.strptime(" ".join(raw.split()), APP_DESC_TS_FMT)
                .replace(tzinfo=dt.UTC)
                .isoformat()
            )
        except ValueError:
            iso = None
        out.append(
            TimelineEntry(
                f"app_desc.date+time of {label} (build time, timezone unknown)",
                raw,
                iso,
                ctx.ev(d.offset + 80, 32, label),
            )
        )
    for label, nvs in ctx.nvs.items():
        for e in (*nvs.entries, *nvs.recovered_deleted):
            iso = _nvs_timestamp(e)
            if iso is None:
                continue
            status = "" if e.status == "written" else " [deleted]"
            out.append(
                TimelineEntry(
                    f"NVS {label}:{e.qualified_key} ({e.type_name}){status}",
                    str(e.value),
                    iso,
                    e.payload[0] if e.payload else e.evidence[0],
                )
            )
    out.sort(key=lambda t: (t.iso is None, t.iso or "", t.ts_source))
    return out


def analyze(
    dump: bytes,
    *,
    reveal_secrets: bool = False,
    baselines: Iterable[str] = (),
    chip: str = "auto",
) -> AnalysisResult:
    ctx = build_context(dump, reveal_secrets=reveal_secrets, baselines=baselines)
    if chip != "auto" and ctx.chip is not None and ctx.chip.chip not in (None, chip):
        ctx.anomalies.append(
            (
                None,
                Anomaly(
                    "CHIP_MISMATCH",
                    f"--chip {chip} but the bootloader header says {ctx.chip.chip}",
                    ctx.chip.bootloader_offset + 12,
                    2,
                    {"requested": chip, "detected": ctx.chip.chip},
                ),
            )
        )
    findings, errors = run_rules(ctx)
    return AnalysisResult(
        ctx=ctx,
        findings=findings,
        timeline=build_timeline(ctx),
        rule_errors=errors,
        chip_requested=chip,
        analysed_at=dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
    )


def write_store(result: AnalysisResult, path: str | Path) -> None:
    ctx = result.ctx
    with EvidenceStore(path) as store:
        store.add_dump(
            ctx.dump_sha256,
            len(ctx.dump),
            result.chip,
            dt.datetime.fromisoformat(result.analysed_at) if result.analysed_at else None,
        )
        for label, info in ctx.partitions.items():
            meta: dict[str, Any] = {
                "type": info.entry.type_name,
                "subtype": info.entry.subtype_name,
                "entropy": round(info.entropy, 4),
                "declared_size": info.entry.size,
            }
            store.add_artifact(
                ctx.dump_sha256,
                "partition",
                label,
                ctx.ev(info.entry.offset, info.entry.size, label),
                meta,
            )
        for label, fs in ctx.filesystems.items():
            for f in fs.files:
                ev = (
                    ctx.ev(f.segments[0].abs_offset, f.segments[0].length, label)
                    if f.segments
                    else ctx.ev(fs.offset, fs.size, label)
                )
                store.add_artifact(
                    ctx.dump_sha256,
                    "file",
                    f.path,
                    ev,
                    {"fs": fs.fs_type, "size": f.size, "sha256": f.sha256, "located": f.located},
                )
        for finding in result.findings:
            store.add_finding(ctx.dump_sha256, finding)
        for t in result.timeline:
            store.add_timeline(
                ctx.dump_sha256, f"{t.ts_source} [{t.trust}]", t.iso or t.value, t.finding_id
            )
