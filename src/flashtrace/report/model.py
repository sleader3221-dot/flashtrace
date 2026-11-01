"""Build the machine-readable report dictionary (schema: docs/report-schema.md)."""

from __future__ import annotations

from typing import Any

from flashtrace.diff import DiffResult
from flashtrace.model import Evidence, Finding
from flashtrace.nvs import NvsEntry
from flashtrace.pipeline import AnalysisResult
from flashtrace.redact import redact
from flashtrace.secrets import SECRETISH_KEY, looks_like_secret_value

SCHEMA_VERSION = "1.0"
PREVIEW_LEN = 64


def evidence_dict(ev: Evidence, dump: bytes | None = None, masked: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "partition": ev.partition,
        "offset": ev.offset,
        "offset_hex": f"{ev.offset:#x}",
        "length": ev.length,
        "sha256": ev.sha256,
    }
    if dump is not None:
        # previews of evidence that backs a redacted secret are withheld
        out["preview_hex"] = (
            None if masked else dump[ev.offset : ev.offset + min(ev.length, PREVIEW_LEN)].hex()
        )
        out["preview_redacted"] = masked
    return out


def finding_dict(f: Finding, dump: bytes | None = None) -> dict[str, Any]:
    masked = f.detail.get("redacted") is True
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "title": f.title,
        "detail": dict(f.detail),
        "evidence": [evidence_dict(e, dump, masked) for e in f.evidence],
        "attck": list(f.attck),
        "confidence": round(f.confidence, 3),
    }


def nvs_value(e: NvsEntry, reveal: bool) -> tuple[Any, bool]:
    """(display value, redacted?) — strings/blobs that look secret are masked."""
    v = e.value
    if v is None or isinstance(v, int):
        return v, False
    raw = v.encode() if isinstance(v, str) else v
    secret = bool(SECRETISH_KEY.search(e.key)) or looks_like_secret_value(raw) is not None
    if secret and not reveal:
        return redact(v, False), True
    if isinstance(v, str):
        return v, False
    shown = v[:PREVIEW_LEN].hex() + ("…" if len(v) > PREVIEW_LEN else "")
    return shown, False


def nvs_entry_dict(e: NvsEntry, reveal: bool) -> dict[str, Any]:
    value, redacted = nvs_value(e, reveal)
    return {
        "namespace": e.namespace,
        "key": e.key,
        "type": e.type_name,
        "status": e.status,
        "value": value,
        "value_redacted": redacted,
        "value_sha256": e.value_sha256,
        "offset": e.offset,
        "offset_hex": f"{e.offset:#x}",
        "page": e.page,
        "slot": e.slot,
        "header_crc_ok": e.header_crc_ok,
        "data_crc_ok": e.data_crc_ok,
        "complete": e.complete,
    }


def result_dict(r: AnalysisResult, *, previews: bool = True) -> dict[str, Any]:
    ctx = r.ctx
    reveal = ctx.reveal_secrets
    dump = ctx.dump if previews else None
    table = ctx.table
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "analysis",
        "tool": {"name": "flashtrace", "version": r.tool_version},
        "dump": {
            "sha256": ctx.dump_sha256,
            "size": len(ctx.dump),
            "chip": r.chip,
            "chip_detected": ctx.chip.chip if ctx.chip else None,
            "chip_id": ctx.chip.chip_id if ctx.chip else None,
            "bootloader_offset": ctx.chip.bootloader_offset if ctx.chip else None,
            "analysed_at": r.analysed_at,
            "secrets_revealed": reveal,
        },
        "encryption": {"likely": ctx.encryption_likely, "reason": ctx.encryption_reason},
        "partition_table": None
        if table is None
        else {
            "offset": table.offset,
            "md5_present": table.md5_present,
            "md5_valid": table.md5_valid,
            "end_marker_found": table.end_marker_found,
        },
        "partitions": [
            {
                "label": label,
                "type": p.entry.type_name,
                "subtype": p.entry.subtype_name,
                "offset": p.entry.offset,
                "offset_hex": f"{p.entry.offset:#x}",
                "size": p.entry.size,
                "present_bytes": p.present,
                "entropy": round(p.entropy, 4),
                "sha256": p.sha256,
                "encrypted_flag": p.entry.encrypted,
                "readonly_flag": p.entry.readonly,
            }
            for label, p in ctx.partitions.items()
        ],
        "apps": [
            {
                "partition": label,
                "offset": img.offset,
                "image_length": img.image_length,
                "chip": img.header.chip if img.header else None,
                "segments": len(img.segments),
                "checksum_valid": img.checksum_valid,
                "sha256_valid": img.sha256_valid,
                "image_sha256": ctx.ev(img.offset, img.image_length, label).sha256
                if img.image_length
                else None,
                "signature_blocks": [
                    {"offset": b.offset, "version": b.version, "scheme": b.scheme}
                    for b in img.signature_blocks
                ],
                "app_desc": None
                if img.app_desc is None
                else {
                    "project_name": img.app_desc.project_name,
                    "version": img.app_desc.version,
                    "secure_version": img.app_desc.secure_version,
                    "idf_ver": img.app_desc.idf_ver,
                    "date": img.app_desc.date,
                    "time": img.app_desc.time,
                    "app_elf_sha256": img.app_desc.app_elf_sha256,
                },
            }
            for label, img in ctx.apps.items()
        ],
        "otadata": None
        if ctx.otadata is None
        else {
            "offset": ctx.otadata.offset,
            "active_slot": ctx.active_slot_label(),
            "entries": [
                {
                    "index": e.index,
                    "offset": e.offset,
                    "seq": e.seq,
                    "state": e.state_name,
                    "crc_ok": e.crc_ok,
                    "valid": e.valid,
                    "erased": e.erased,
                }
                for e in ctx.otadata.entries
            ],
        },
        "nvs": [
            {
                "partition": label,
                "encrypted": n.encrypted,
                "encryption_reason": n.encryption_reason,
                "pages": len(n.pages),
                "namespaces": {str(k): v for k, v in sorted(n.namespaces.items())},
                "entries": [nvs_entry_dict(e, reveal) for e in n.entries],
                "recovered_deleted": [nvs_entry_dict(e, reveal) for e in n.recovered_deleted],
            }
            for label, n in ctx.nvs.items()
        ],
        "filesystems": [
            {
                "partition": label,
                "type": fs.fs_type,
                "mounted": fs.mounted,
                "detail": fs.detail,
                "directories": list(fs.directories),
                "files": [
                    {
                        "path": f.path,
                        "size": f.size,
                        "sha256": f.sha256,
                        "located": f.located,
                        "complete": f.complete,
                        "offset": f.segments[0].abs_offset if f.segments else None,
                    }
                    for f in fs.files
                ],
            }
            for label, fs in ctx.filesystems.items()
        ],
        "coredump": None
        if ctx.coredump is None
        else {
            "partition": ctx.coredump.partition,
            "format": ctx.coredump.format,
            "size": ctx.coredump.size,
            "data_len": ctx.coredump.data_len,
            "tasks": ctx.coredump.tasks_num,
        },
        "summary": {
            "finding_count": len(r.findings),
            "severity_counts": r.severity_counts(),
            "max_severity": r.max_severity(),
            "rules_fired": sorted({f.rule_id for f in r.findings}),
        },
        "findings": [finding_dict(f, dump) for f in r.findings],
        "timeline": [
            {
                "ts_source": t.ts_source,
                "value": t.value,
                "iso": t.iso,
                "trust": t.trust,
                "evidence": evidence_dict(t.evidence),
            }
            for t in r.timeline
        ],
        "rule_errors": list(r.rule_errors),
    }


def _diff_finding(f: Finding, d: DiffResult) -> dict[str, Any]:
    out = finding_dict(f)
    dumps = f.detail.get("evidence_dumps", [])
    masked = f.detail.get("redacted") is True
    for i, ev in enumerate(f.evidence):
        src = d.a.dump if i < len(dumps) and dumps[i] == "A" else d.b.dump
        out["evidence"][i] = {
            **evidence_dict(ev, src, masked),
            "dump": dumps[i] if i < len(dumps) else "B",
        }
    return out


def diff_dict(d: DiffResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "diff",
        "dump_a": {"sha256": d.a.dump_sha256, "size": len(d.a.dump)},
        "dump_b": {"sha256": d.b.dump_sha256, "size": len(d.b.dump)},
        "summary": {
            "finding_count": len(d.findings),
            "rules_fired": sorted({f.rule_id for f in d.findings}),
        },
        "findings": [_diff_finding(f, d) for f in d.findings],
    }
