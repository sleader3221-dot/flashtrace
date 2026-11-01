"""Compare two dumps partition by partition and emit DIFF.* findings.

Evidence always points into the dump the bytes come from; ``detail["evidence_dumps"]``
lists, per evidence item, whether it refers to dump "A" or dump "B".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from flashtrace.attck import enrich
from flashtrace.context import AnalysisContext, build_context
from flashtrace.model import Evidence, Finding, Severity, make_finding
from flashtrace.nvs import NvsEntry
from flashtrace.redact import redact

DIFF_RULES: dict[str, tuple[Severity, str]] = {
    "DIFF.PARTITION_TABLE": ("medium", "Partition table changed"),
    "DIFF.PARTITION_CHANGED": ("info", "Partition contents changed"),
    "DIFF.APP_DESC": ("medium", "App descriptor changed"),
    "DIFF.OTA_STATE": ("low", "OTA selection/state changed"),
    "DIFF.NVS_ADDED": ("info", "NVS key added"),
    "DIFF.NVS_REMOVED": ("info", "NVS key removed"),
    "DIFF.NVS_CHANGED": ("info", "NVS value changed"),
    "DIFF.FS_ADDED": ("info", "File added"),
    "DIFF.FS_REMOVED": ("info", "File removed"),
    "DIFF.FS_CHANGED": ("info", "File changed"),
}


@dataclass
class DiffResult:
    a: AnalysisContext
    b: AnalysisContext
    findings: list[Finding] = field(default_factory=list)

    def has_high(self) -> bool:
        return any(f.severity in ("high", "critical") for f in self.findings)


def _f(rule: str, title: str, detail: dict[str, Any], ev: list[tuple[str, Evidence]]) -> Finding:
    sev, _ = DIFF_RULES[rule]
    return make_finding(
        rule,
        severity=sev,
        title=title,
        detail={**detail, "evidence_dumps": [d for d, _ in ev]},
        evidence=tuple(e for _, e in ev),
    )


def _nvs_index(ctx: AnalysisContext) -> dict[tuple[str, str, str], NvsEntry]:
    out: dict[tuple[str, str, str], NvsEntry] = {}
    for label, nvs in ctx.nvs.items():
        for e in nvs.entries:
            out[(label, e.namespace or f"ns#{e.ns_index}", e.key)] = e  # last write wins
    return out


def _shown(e: NvsEntry, reveal: bool) -> str:
    v = e.value
    if isinstance(v, int):
        return str(v)
    if v is None:
        return "<unrecoverable>"
    return redact(v, reveal)


def diff_contexts(a: AnalysisContext, b: AnalysisContext, reveal: bool = False) -> DiffResult:
    res = DiffResult(a, b)
    out = res.findings
    # partition table
    ta = {e.label: e for e in (a.table.entries if a.table else ())}
    tb = {e.label: e for e in (b.table.entries if b.table else ())}
    for label in sorted(set(ta) | set(tb)):
        ea, eb = ta.get(label), tb.get(label)
        sig_a = None if ea is None else (ea.type, ea.subtype, ea.offset, ea.size, ea.flags)
        sig_b = None if eb is None else (eb.type, eb.subtype, eb.offset, eb.size, eb.flags)
        if sig_a != sig_b:
            ev: list[tuple[str, Evidence]] = []
            if ea is not None:
                ev.append(("A", a.ev(ea.entry_offset, 32, None)))
            if eb is not None:
                ev.append(("B", b.ev(eb.entry_offset, 32, None)))
            out.append(
                _f(
                    "DIFF.PARTITION_TABLE",
                    f"Partition {label!r} "
                    + ("added" if ea is None else "removed" if eb is None else "changed"),
                    {"label": label, "a": sig_a, "b": sig_b},
                    ev,
                )
            )
    # partition contents
    for label in sorted(set(a.partitions) & set(b.partitions)):
        pa, pb = a.partitions[label], b.partitions[label]
        if pa.sha256 != pb.sha256:
            out.append(
                _f(
                    "DIFF.PARTITION_CHANGED",
                    f"Partition {label!r} contents changed",
                    {"label": label, "sha256_a": pa.sha256, "sha256_b": pb.sha256},
                    [
                        ("A", a.ev(pa.entry.offset, pa.entry.size, label)),
                        ("B", b.ev(pb.entry.offset, pb.entry.size, label)),
                    ],
                )
            )
    # app descriptors
    for label in sorted(set(a.apps) | set(b.apps)):
        da = a.apps[label].app_desc if label in a.apps else None
        db = b.apps[label].app_desc if label in b.apps else None
        fields = ("project_name", "version", "idf_ver", "secure_version", "date", "time")
        va = {k: getattr(da, k) for k in fields} if da else None
        vb = {k: getattr(db, k) for k in fields} if db else None
        if va != vb:
            ev = []
            if da:
                ev.append(("A", a.ev(da.offset, 256, label)))
            if db:
                ev.append(("B", b.ev(db.offset, 256, label)))
            if ev:
                changed = sorted(k for k in fields if (va or {}).get(k) != (vb or {}).get(k))
                out.append(
                    _f(
                        "DIFF.APP_DESC",
                        f"App descriptor of {label} changed: {', '.join(changed)}",
                        {"label": label, "a": va, "b": vb, "changed": changed},
                        ev,
                    )
                )

    # OTA state
    def ota_sig(ctx: AnalysisContext) -> dict[str, Any] | None:
        o = ctx.otadata
        if o is None:
            return None
        return {
            "active_slot": ctx.active_slot_label(),
            "entries": [(e.seq, e.state_name, e.crc_ok) for e in o.entries],
        }

    sa, sb = ota_sig(a), ota_sig(b)
    if sa != sb:
        ev = []
        if a.otadata:
            ev.append(("A", a.ev(a.otadata.offset, 0x2000, None)))
        if b.otadata:
            ev.append(("B", b.ev(b.otadata.offset, 0x2000, None)))
        if ev:
            out.append(_f("DIFF.OTA_STATE", "OTA selection/state changed", {"a": sa, "b": sb}, ev))
    # NVS
    na, nb = _nvs_index(a), _nvs_index(b)
    for key in sorted(set(na) | set(nb)):
        ea_, eb_ = na.get(key), nb.get(key)
        qk = f"{key[0]}:{key[1]}/{key[2]}"
        if ea_ is None and eb_ is not None:
            out.append(
                _f(
                    "DIFF.NVS_ADDED",
                    f"NVS {qk} added",
                    {"key": qk, "b": _shown(eb_, reveal), "type": eb_.type_name},
                    [("B", eb_.evidence[0])],
                )
            )
        elif eb_ is None and ea_ is not None:
            out.append(
                _f(
                    "DIFF.NVS_REMOVED",
                    f"NVS {qk} removed",
                    {"key": qk, "a": _shown(ea_, reveal), "type": ea_.type_name},
                    [("A", ea_.evidence[0])],
                )
            )
        elif ea_ is not None and eb_ is not None and ea_.value_sha256 != eb_.value_sha256:
            out.append(
                _f(
                    "DIFF.NVS_CHANGED",
                    f"NVS {qk} changed",
                    {"key": qk, "a": _shown(ea_, reveal), "b": _shown(eb_, reveal)},
                    [("A", ea_.evidence[0]), ("B", eb_.evidence[0])],
                )
            )

    # filesystems
    def files(ctx: AnalysisContext) -> dict[tuple[str, str], tuple[str, Evidence]]:
        out_: dict[tuple[str, str], tuple[str, Evidence]] = {}
        for label, fs in ctx.filesystems.items():
            for f in fs.files:
                ev_ = (
                    ctx.ev(f.segments[0].abs_offset, f.segments[0].length, label)
                    if f.segments
                    else ctx.ev(fs.offset, fs.size, label)
                )
                out_[(label, f.path)] = (f.sha256, ev_)
        return out_

    fa, fb = files(a), files(b)
    for fkey in sorted(set(fa) | set(fb)):
        name = f"{fkey[0]}:{fkey[1]}"
        if fkey not in fa:
            out.append(
                _f("DIFF.FS_ADDED", f"File {name} added", {"path": name}, [("B", fb[fkey][1])])
            )
        elif fkey not in fb:
            out.append(
                _f("DIFF.FS_REMOVED", f"File {name} removed", {"path": name}, [("A", fa[fkey][1])])
            )
        elif fa[fkey][0] != fb[fkey][0]:
            out.append(
                _f(
                    "DIFF.FS_CHANGED",
                    f"File {name} changed",
                    {"path": name, "sha256_a": fa[fkey][0], "sha256_b": fb[fkey][0]},
                    [("A", fa[fkey][1]), ("B", fb[fkey][1])],
                )
            )
    res.findings = enrich(res.findings)
    return res


def diff_dumps(a: bytes, b: bytes, reveal: bool = False) -> DiffResult:
    return diff_contexts(build_context(a), build_context(b), reveal)
