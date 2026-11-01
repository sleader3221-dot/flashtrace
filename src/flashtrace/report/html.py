"""Single self-contained HTML report (inline CSS/JS, no external resources)."""

from __future__ import annotations

import html
import json
from typing import Any

from flashtrace.model import SEVERITIES

TYPE_COLORS = {
    "app": "#4f7cac",
    "ota": "#c47f2c",
    "nvs": "#3f9a6b",
    "nvs_keys": "#2d6e4c",
    "phy": "#8a8f98",
    "coredump": "#b04a4a",
    "spiffs": "#7a5aa6",
    "littlefs": "#7a5aa6",
    "fat": "#7a5aa6",
}
CSS = """
:root{--bg:#fff;--fg:#1d2330;--muted:#5f6b7a;--card:#f4f6f9;--border:#d9dee5;
--critical:#8b1d2c;--high:#c0392b;--medium:#d68910;--low:#2e86c1;--info:#6c7a89}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ee;--muted:#9aa5b1;
--card:#1e232b;--border:#2e3540}}
*{box-sizing:border-box}body{margin:0;padding:16px;background:var(--bg);color:var(--fg);
font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:1200px;margin:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid
var(--border);padding-bottom:4px}code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;
font-size:12.5px}.muted{color:var(--muted)}.meta{display:grid;grid-template-columns:max-content 1fr;
gap:2px 12px;margin-top:8px}.meta div:nth-child(odd){color:var(--muted)}
.meta div{overflow-wrap:anywhere}.cards{display:flex;flex-wrap:wrap;gap:8px}
.card{background:var(--card);border:1px solid var(--border);border-left:5px solid;border-radius:6px;
padding:8px 14px;min-width:96px}.card b{display:block;font-size:22px}
.sev-critical{border-left-color:var(--critical)}.sev-high{border-left-color:var(--high)}
.sev-medium{border-left-color:var(--medium)}.sev-low{border-left-color:var(--low)}
.sev-info{border-left-color:var(--info)}.pill{display:inline-block;border-radius:10px;padding:0 8px;
color:#fff;font-size:12px}.pill.critical{background:var(--critical)}.pill.high{background:var(--high)}
.pill.medium{background:var(--medium)}.pill.low{background:var(--low)}.pill.info{background:var(--info)}
.map{display:flex;height:34px;border:1px solid var(--border);border-radius:4px;overflow:hidden}
.map div{height:100%;min-width:2px;border-right:1px solid var(--bg);color:#fff;font-size:11px;
overflow:hidden;white-space:nowrap;padding:2px 3px}.legend{font-size:12px;margin-top:4px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 6px;border-bottom:1px
solid var(--border);vertical-align:top}.tablewrap{overflow-x:auto}
details{border:1px solid var(--border);border-radius:6px;margin:6px 0;background:var(--card)}
summary{cursor:pointer;padding:8px 10px;list-style:none}
summary::-webkit-details-marker{display:none}
details>div{padding:4px 12px 12px}pre{margin:6px 0;overflow-x:auto;white-space:pre}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}select{padding:4px;background:var(--card);
color:var(--fg);border:1px solid var(--border);border-radius:4px}
"""
JS = """
function ftFilter(){var s=document.getElementById('f-sev').value,
r=document.getElementById('f-rule').value;
document.querySelectorAll('details.finding').forEach(function(d){
var ok=(!s||d.dataset.sev===s)&&(!r||d.dataset.rule===r);d.style.display=ok?'':'none';});}
"""


def _e(x: Any) -> str:
    return html.escape("" if x is None else str(x), quote=True)


def hexdump(hexstr: str | None, base: int, redacted: bool = True) -> str:
    if hexstr is None:
        if redacted:
            return "(preview withheld: evidence backs a redacted secret; use --reveal-secrets)"
        return "(no preview available)"
    raw = bytes.fromhex(hexstr)
    rows = []
    for i in range(0, len(raw), 16):
        chunk = raw[i : i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{base + i:08x}  {hx:<47}  {asc}")
    return "\n".join(rows) or "(empty)"


def _findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p class='muted'>No findings.</p>"
    rules = sorted({f["rule_id"] for f in findings})
    parts = [
        "<div class='filters'><label>Severity <select id='f-sev' onchange='ftFilter()'>"
        "<option value=''>all</option>"
        + "".join(f"<option>{s}</option>" for s in reversed(SEVERITIES))
        + "</select></label><label>Rule <select id='f-rule' onchange='ftFilter()'>"
        "<option value=''>all</option>"
        + "".join(f"<option>{_e(r)}</option>" for r in rules)
        + "</select></label></div>"
    ]
    for f in findings:
        evs = []
        for ev in f["evidence"]:
            evs.append(
                "<tr><td class='mono'>{}</td><td>{}</td><td>{}{}</td><td class='mono'>{}</td></tr>"
                "<tr><td colspan='4'><pre class='mono'>{}</pre></td></tr>".format(
                    _e(ev["offset_hex"]),
                    _e(ev["length"]),
                    _e(ev["partition"] or "-"),
                    _e(f" (dump {ev['dump']})" if "dump" in ev else ""),
                    _e(ev["sha256"]),
                    _e(
                        hexdump(
                            ev.get("preview_hex"), ev["offset"], bool(ev.get("preview_redacted"))
                        )
                    ),
                )
            )
        detail = json.dumps(f["detail"], indent=2, default=str)
        parts.append(
            f"<details class='finding' data-sev='{_e(f['severity'])}'"
            f" data-rule='{_e(f['rule_id'])}'>"
            f"<summary><span class='pill {_e(f['severity'])}'>{_e(f['severity'])}</span> "
            f"<code>{_e(f['rule_id'])}</code> {_e(f['title'])}</summary><div>"
            f"<div class='muted'>id <code>{_e(f['id'])}</code> · confidence {_e(f['confidence'])}"
            f" · ATT&amp;CK for ICS: {_e(', '.join(f['attck']) or 'none mapped')}</div>"
            f"<pre class='mono'>{_e(detail)}</pre><div class='tablewrap'><table>"
            "<tr><th>Offset</th><th>Length</th><th>Partition</th><th>SHA-256</th></tr>"
            + "".join(evs)
            + "</table></div></div></details>"
        )
    return "".join(parts)


def _partition_map(data: dict[str, Any]) -> str:
    size = data["dump"]["size"] or 1
    parts = sorted(data["partitions"], key=lambda p: p["offset"])
    cells = []
    cursor = 0
    for p in parts:
        if p["offset"] > cursor:
            w = (p["offset"] - cursor) / size * 100
            cells.append(
                f"<div style='width:{w:.3f}%;background:#cfd5dd' title='unpartitioned'></div>"
            )
        color = TYPE_COLORS.get(p["subtype"], TYPE_COLORS.get(p["type"], "#5d6d7e"))
        w = min(p["size"], max(size - p["offset"], 0)) / size * 100
        cells.append(
            f"<div style='width:{w:.3f}%;background:{color}' title='{_e(p['label'])} "
            f"{_e(p['offset_hex'])} {p['size']} B entropy {p['entropy']:.2f}'>"
            f"{_e(p['label'])}</div>"
        )
        cursor = max(cursor, p["offset"] + p["size"])
    rows = "".join(
        f"<tr><td>{_e(p['label'])}</td><td>{_e(p['type'])}/{_e(p['subtype'])}</td>"
        f"<td class='mono'>{_e(p['offset_hex'])}</td><td>{p['size']}</td>"
        f"<td>{p['entropy']:.2f}</td><td class='mono'>{_e(p['sha256'][:16])}…</td></tr>"
        for p in parts
    )
    return (
        f"<div class='map'>{''.join(cells)}</div>"
        "<div class='legend muted'>Bar widths are proportional to flash offsets; hover for"
        " entropy (bits/byte).</div><div class='tablewrap'><table><tr><th>Label</th><th>Type"
        "</th><th>Offset</th><th>Size</th><th>Entropy</th><th>SHA-256</th></tr>"
        f"{rows}</table></div>"
    )


def _deleted(data: dict[str, Any]) -> str:
    rows = [
        f"<tr><td>{_e(n['partition'])}</td><td><code>{_e(e['namespace'])}/{_e(e['key'])}</code></td>"
        f"<td>{_e(e['type'])}</td><td class='mono'>{_e(e['value'])}</td>"
        f"<td class='mono'>{_e(e['offset_hex'])}</td>"
        f"<td class='mono'>{_e((e['value_sha256'] or '')[:16])}</td></tr>"
        for n in data["nvs"]
        for e in n["recovered_deleted"]
    ]
    if not rows:
        return "<p class='muted'>None recovered.</p>"
    return (
        "<div class='tablewrap'><table><tr><th>Partition</th><th>Key</th><th>Type</th><th>Value"
        "</th><th>Offset</th><th>Value SHA-256</th></tr>" + "".join(rows) + "</table></div>"
    )


def _timeline(data: dict[str, Any]) -> str:
    if not data["timeline"]:
        return "<p class='muted'>No device-reported timestamps.</p>"
    rows = "".join(
        f"<tr><td class='mono'>{_e(t['iso'] or '-')}</td><td class='mono'>{_e(t['value'])}</td>"
        f"<td>{_e(t['ts_source'])}</td><td class='mono'>{_e(t['evidence']['offset_hex'])}</td></tr>"
        for t in data["timeline"]
    )
    return (
        "<p class='muted'>Device-reported values, not trusted wall-clock time.</p>"
        "<div class='tablewrap'><table><tr><th>Normalised (UTC)</th><th>Raw value</th>"
        f"<th>Source</th><th>Evidence</th></tr>{rows}</table></div>"
    )


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_e(title)}</title><style>{CSS}</style></head><body>{body}"
        f"<script>{JS}</script></body></html>\n"
    )


def render(data: dict[str, Any]) -> str:
    if data.get("kind") == "diff":
        return render_diff(data)
    d, s = data["dump"], data["summary"]
    cards = "".join(
        f"<div class='card sev-{k}'><b>{s['severity_counts'].get(k, 0)}</b>{k}</div>"
        for k in reversed(SEVERITIES)
    )
    enc = (
        f"<p><b>Flash encryption likely enabled:</b> {_e(data['encryption']['reason'])}."
        " Structural parsing was skipped.</p>"
        if data["encryption"]["likely"]
        else ""
    )
    body = (
        "<header><h1>FlashTrace report</h1><div class='meta'>"
        f"<div>Dump SHA-256</div><div class='mono'>{_e(d['sha256'])}</div>"
        f"<div>Size</div><div>{d['size']} bytes</div>"
        f"<div>Chip</div><div>{_e(d['chip'] or 'unknown')}</div>"
        f"<div>Analysed</div><div>{_e(d['analysed_at'])}</div>"
        f"<div>Tool</div><div>flashtrace {_e(data['tool']['version'])}</div>"
        f"<div>Secrets</div><div>{'REVEALED' if d['secrets_revealed'] else 'redacted'}</div>"
        + (
            "<div>Decrypted view</div><div>flash "
            f"{_e(d['decryption']['flash_scheme'] or 'not encrypted')}, NVS "
            f"{_e(', '.join(d['decryption']['nvs_partitions']) or 'none')}; evidence hashes"
            " refer to decrypted bytes</div>"
            if d.get("decryption")
            else ""
        )
        + "</div></header>"
        f"<h2 id='summary'>Severity summary</h2><div class='cards'>{cards}</div>{enc}"
        f"<h2 id='partitions'>Partition map</h2>{_partition_map(data)}"
        f"<h2 id='findings'>Findings</h2>{_findings(data['findings'])}"
        f"<h2 id='deleted-nvs'>Recovered deleted NVS entries</h2>{_deleted(data)}"
        f"<h2 id='timeline'>Device-reported timeline</h2>{_timeline(data)}"
    )
    return _page(f"FlashTrace {d['sha256'][:12]}", body)


def render_diff(data: dict[str, Any]) -> str:
    a, b = data["dump_a"], data["dump_b"]
    body = (
        "<header><h1>FlashTrace diff</h1><div class='meta'>"
        f"<div>Dump A</div><div class='mono'>{_e(a['sha256'])} ({a['size']} bytes)</div>"
        f"<div>Dump B</div><div class='mono'>{_e(b['sha256'])} ({b['size']} bytes)</div>"
        f"<div>Differences</div><div>{data['summary']['finding_count']}</div></div></header>"
        f"<h2 id='diff'>Diff view</h2>{_findings(data['findings'])}"
    )
    return _page("FlashTrace diff", body)
