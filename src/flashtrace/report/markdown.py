"""Markdown report: executive summary, severity counts, findings table."""

from __future__ import annotations

from typing import Any

from flashtrace.model import SEVERITIES


def _esc(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _findings_table(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Severity | Rule | Finding | Evidence (first) | ATT&CK |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        ev = f["evidence"][0] if f["evidence"] else None
        ev_s = (
            f"`{ev['offset_hex']}` +{ev['length']} ({ev['partition'] or '-'}) "
            f"sha256 `{ev['sha256'][:16]}…`"
            if ev
            else "-"
        )
        lines.append(
            f"| {f['severity']} | `{f['rule_id']}` | {_esc(f['title'])} | {ev_s} |"
            f" {', '.join(f['attck']) or '-'} |"
        )
    return lines


def render(data: dict[str, Any]) -> str:
    if data.get("kind") == "diff":
        return render_diff(data)
    d, s = data["dump"], data["summary"]
    counts = s["severity_counts"]
    lines = [
        "# FlashTrace report",
        "",
        f"- **Dump SHA-256:** `{d['sha256']}`",
        f"- **Size:** {d['size']} bytes",
        f"- **Chip:** {d['chip'] or 'unknown'}"
        + (
            f" (bootloader at `{d['bootloader_offset']:#x}`)"
            if d["bootloader_offset"] is not None
            else ""
        ),
        f"- **Analysed:** {d['analysed_at']} with flashtrace {data['tool']['version']}",
        f"- **Secrets:** {'REVEALED' if d['secrets_revealed'] else 'redacted'}",
        "",
        "## Executive summary",
        "",
    ]
    if data["encryption"]["likely"]:
        lines.append(f"Flash encryption is likely enabled: {data['encryption']['reason']}.")
        lines.append("Structural parsing was skipped; findings are limited accordingly.")
    elif not data["findings"]:
        lines.append("No findings.")
    else:
        top = [f for f in data["findings"] if f["severity"] in ("critical", "high")]
        lines.append(
            f"{s['finding_count']} findings; highest severity **{s['max_severity']}**."
            + (f" {len(top)} high/critical finding(s) need attention:" if top else "")
        )
        lines.extend(
            f"- **{f['severity']}** `{f['rule_id']}` — {_esc(f['title'])}" for f in top[:10]
        )
    lines += [
        "",
        "## Severity counts",
        "",
        "| " + " | ".join(SEVERITIES) + " |",
        "|" + "---:|" * len(SEVERITIES),
        "| " + " | ".join(str(counts.get(k, 0)) for k in SEVERITIES) + " |",
        "",
        "## Findings",
        "",
        *(_findings_table(data["findings"]) if data["findings"] else ["None."]),
        "",
        "## Partitions",
        "",
        "| Label | Type | Subtype | Offset | Size | Entropy |",
        "|---|---|---|---|---:|---:|",
    ]
    for p in data["partitions"]:
        lines.append(
            f"| {_esc(p['label'])} | {p['type']} | {p['subtype']} | `{p['offset_hex']}` |"
            f" {p['size']} | {p['entropy']:.2f} |"
        )
    deleted = [(n["partition"], e) for n in data["nvs"] for e in n["recovered_deleted"]]
    lines += ["", "## Recovered deleted NVS entries", ""]
    if deleted:
        lines += ["| Partition | Key | Type | Value | Offset |", "|---|---|---|---|---|"]
        for part, e in deleted:
            lines.append(
                f"| {part} | `{_esc(e['namespace'])}/{_esc(e['key'])}` | {e['type']} |"
                f" {_esc(e['value'])} | `{e['offset_hex']}` |"
            )
    else:
        lines.append("None.")
    lines += ["", "## Device-reported timeline (untrusted)", ""]
    if data["timeline"]:
        lines += ["| Value | Normalised (UTC) | Source |", "|---|---|---|"]
        for t in data["timeline"]:
            lines.append(f"| {_esc(t['value'])} | {t['iso'] or '-'} | {_esc(t['ts_source'])} |")
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def render_diff(data: dict[str, Any]) -> str:
    lines = [
        "# FlashTrace diff",
        "",
        f"- **A:** `{data['dump_a']['sha256']}` ({data['dump_a']['size']} bytes)",
        f"- **B:** `{data['dump_b']['sha256']}` ({data['dump_b']['size']} bytes)",
        f"- **Differences:** {data['summary']['finding_count']}",
        "",
        *(_findings_table(data["findings"]) if data["findings"] else ["No differences."]),
    ]
    return "\n".join(lines) + "\n"
