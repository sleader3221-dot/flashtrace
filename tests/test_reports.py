from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from flashtrace.diff import diff_dumps
from flashtrace.pipeline import analyze
from flashtrace.report import html, json_report, markdown
from flashtrace.report.model import diff_dict, result_dict
from tools.corpus.generate import build_device, devices

SNAP = Path(__file__).parent / "snapshots"
FIXED_TIME = "2026-01-01T00:00:00+00:00"


def device(name: str) -> bytes:
    dev = next(d for d in devices() if d.name == name)
    return build_device(dev, use_esptool=False)[0]


def report(name: str, **kw: object) -> dict[str, object]:
    return result_dict(analyze(device(name), analysed_at=FIXED_TIME, **kw))  # type: ignore[arg-type]


def snapshot(name: str, text: str) -> None:
    path = SNAP / name
    if os.environ.get("UPDATE_SNAPSHOTS") == "1" or not path.exists():
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), f"snapshot {name} changed"


def test_json_snapshot() -> None:
    data = report("deleted_token_in_nvs")
    text = json_report.dumps(data)
    snapshot("deleted_token_in_nvs.json", text)
    parsed = json.loads(text)
    assert parsed["schema_version"] == "1.0" and parsed["kind"] == "analysis"
    assert parsed["nvs"][0]["recovered_deleted"]


def test_markdown_snapshot() -> None:
    md = markdown.render(report("wifi_creds_in_nvs"))
    snapshot("wifi_creds_in_nvs.md", md)
    for heading in ("## Executive summary", "## Severity counts", "## Findings"):
        assert heading in md


def test_redaction_in_reports() -> None:
    data = report("wifi_creds_in_nvs")
    text = json_report.dumps(data)
    assert "example-wifi-passphrase" not in text
    f = next(x for x in data["findings"] if x["rule_id"] == "NVS.WIFI_CREDENTIALS")  # type: ignore[index]
    assert all(ev["preview_hex"] is None for ev in f["evidence"])
    revealed = json_report.dumps(report("wifi_creds_in_nvs", reveal_secrets=True))
    assert "example-wifi-passphrase" in revealed


@pytest.mark.parametrize("name", ["pem_private_key_in_spiffs", "deleted_token_in_nvs"])
def test_html_smoke(name: str) -> None:
    page = html.render(report(name))
    for anchor in (
        "id='summary'",
        "id='partitions'",
        "id='findings'",
        "id='deleted-nvs'",
        "id='timeline'",
    ):
        assert anchor in page
    assert "class='map'" in page and "ftFilter()" in page and "<details class='finding'" in page
    # self-contained: no external scripts, stylesheets, images, fonts or imports
    assert not re.search(r"<(script|link|img|iframe)[^>]+(src|href)\s*=", page, re.I)
    assert not re.search(r"url\(|@import", page, re.I)
    assert "PRIVATE KEY-----\n" not in page


def test_html_diff_view() -> None:
    res = diff_dumps(device("clean_control"), device("forced_rollback"))
    page = html.render(diff_dict(res))
    assert "id='diff'" in page and "DIFF.OTA_STATE" in page and "DIFF.APP_DESC" in page
    md = markdown.render(diff_dict(res))
    assert md.startswith("# FlashTrace diff")
    assert "preview withheld" not in page and "(dump A)" in page and "(dump B)" in page
    sev = [f.severity for f in res.findings]
    order = ["critical", "high", "medium", "low", "info"]
    assert sev == sorted(sev, key=order.index)


def test_encrypted_report_mentions_skip() -> None:
    md = markdown.render(report("encrypted_flash_simulated"))
    assert "Flash encryption is likely enabled" in md
