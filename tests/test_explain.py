from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from flashtrace.commands import EXIT_ERROR, EXIT_OK, fallback_main
from flashtrace.explain import DEFAULT_MODEL, ExplainError, explain_report, render_markdown
from flashtrace.pipeline import analyze
from flashtrace.report.model import result_dict
from tools.corpus.generate import build_device, devices


class FakeMessages:
    def __init__(self, reply: dict[str, Any] | str, stop_reason: str = "end_turn") -> None:
        self.reply, self.stop_reason, self.calls = reply, stop_reason, []

    def create(self, **kw: Any) -> Any:
        self.calls.append(kw)
        text = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return SimpleNamespace(
            stop_reason=self.stop_reason,
            model=kw["model"],
            content=[SimpleNamespace(type="text", text=text)],
        )


def fake(reply: dict[str, Any] | str, stop_reason: str = "end_turn") -> Any:
    msgs = FakeMessages(reply, stop_reason)
    return SimpleNamespace(beta=SimpleNamespace(messages=msgs)), msgs


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    dev = next(d for d in devices() if d.name == "wifi_creds_in_nvs")
    return result_dict(analyze(build_device(dev, use_esptool=False)[0]))


def test_explanations_are_bound_to_existing_findings(report: dict[str, Any]) -> None:
    ids = [f["id"] for f in report["findings"]]
    client, msgs = fake(
        {
            "summary": "Wi-Fi credentials are exposed.",
            "explanations": [
                {
                    "finding_id": ids[0],
                    "explanation": "The passphrase is stored.",
                    "next_steps": ["Rotate it"],
                },
                {"finding_id": "NEW.RULE:deadbeef", "explanation": "invented", "next_steps": []},
            ],
        }
    )
    exp = explain_report(report, client=client)
    assert list(exp.by_finding) == [ids[0]] and exp.dropped == 1
    assert exp.unexplained == ids[1:]
    # request shape: default model, structured output, fallbacks, redacted data only
    kw = msgs.calls[0]
    assert kw["model"] == DEFAULT_MODEL and kw["fallbacks"] == "default"
    assert kw["output_config"]["format"]["type"] == "json_schema"
    sent = kw["messages"][0]["content"]
    assert "example-wifi-passphrase" not in sent and "preview_hex" not in sent
    md = render_markdown(exp, report)
    assert "Rotate it" in md and "not evidence" in md


@pytest.mark.parametrize(
    ("stop", "reply", "msg"),
    [
        ("refusal", "{}", "declined"),
        ("max_tokens", "{}", "cut off"),
        ("end_turn", "not json", "invalid JSON"),
    ],
)
def test_bad_responses_raise(report: dict[str, Any], stop: str, reply: str, msg: str) -> None:
    client, _ = fake(reply, stop)
    with pytest.raises(ExplainError, match=msg):
        explain_report(report, client=client)


def test_revealed_reports_are_refused(report: dict[str, Any]) -> None:
    revealed = {**report, "dump": {**report["dump"], "secrets_revealed": True}}
    client, msgs = fake({"summary": "", "explanations": []})
    with pytest.raises(ExplainError, match="reveal-secrets"):
        explain_report(revealed, client=client)
    assert msgs.calls == []
    explain_report(revealed, client=client, allow_revealed=True)


def test_empty_and_invalid_input() -> None:
    client, msgs = fake({"summary": "", "explanations": []})
    empty = {"kind": "analysis", "dump": {}, "findings": []}
    assert explain_report(empty, client=client).summary.startswith("The report contains no")
    assert msgs.calls == []  # no API call when there is nothing to explain
    with pytest.raises(ExplainError, match="not a FlashTrace"):
        explain_report({"hello": 1}, client=client)


def test_cli_explain_errors_cleanly(tmp_path: Path) -> None:
    bad = tmp_path / "r.json"
    bad.write_text("{not json")
    assert fallback_main(["explain", str(bad), "--out", str(tmp_path / "x")]) == EXIT_ERROR
    empty = tmp_path / "e.json"
    empty.write_text(json.dumps({"kind": "analysis", "dump": {}, "findings": []}))
    assert fallback_main(["explain", str(empty), "--out", str(tmp_path / "x")]) == EXIT_OK
    assert (tmp_path / "x" / "explanation.md").is_file()
