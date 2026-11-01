"""Benchmark: run analysis over a ground-truth corpus and score every rule.

Corpus layout: ``<corpus>/<device>/{dump.bin, ground_truth.json, baselines/*.bin}``.
Per device and rule: listed in ``must_fire`` and fired -> TP, not fired -> FN;
listed in ``must_not_fire`` and fired -> FP. ``dont_care`` rules are not scored.

Gate (CI fails when any is violated):
* overall recall >= 0.95;
* no forbidden (``must_not_fire``) rule fires on any device;
* on ``clean_control``, no finding of severity >= medium whose rule is not in its
  ``must_fire`` list (the clean device's only expected finding is the inherent
  plaintext-flash posture finding, see PROGRESS.md "Blocked / needs human").
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flashtrace.pipeline import SEVERITY_RANK, analyze, load_baselines

RECALL_GATE = 0.95
CLEAN_DEVICE = "clean_control"


@dataclass
class RuleScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return None if self.tp + self.fp == 0 else self.tp / (self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return None if self.tp + self.fn == 0 else self.tp / (self.tp + self.fn)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None if p is None or r is None else 0.0
        return 2 * p * r / (p + r)

    def as_dict(self) -> dict[str, Any]:
        def rnd(x: float | None) -> float | None:
            return None if x is None else round(x, 4)

        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": rnd(self.precision),
            "recall": rnd(self.recall),
            "f1": rnd(self.f1),
        }


@dataclass
class BenchResult:
    per_rule: dict[str, RuleScore] = field(default_factory=dict)
    devices: list[dict[str, Any]] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    @property
    def overall(self) -> RuleScore:
        total = RuleScore()
        for s in self.per_rule.values():
            total.tp += s.tp
            total.fp += s.fp
            total.fn += s.fn
        return total

    @property
    def passed(self) -> bool:
        return not self.violations

    def as_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.as_dict(),
            "gate": {
                "recall_threshold": RECALL_GATE,
                "passed": self.passed,
                "violations": self.violations,
            },
            "per_rule": {k: v.as_dict() for k, v in sorted(self.per_rule.items())},
            "devices": self.devices,
        }


def run_bench(corpus: Path) -> BenchResult:
    res = BenchResult()
    device_dirs = sorted(p for p in corpus.iterdir() if (p / "ground_truth.json").is_file())
    if not device_dirs:
        res.violations.append(f"no devices with ground_truth.json under {corpus}")
        return res
    for d in device_dirs:
        gt = json.loads((d / "ground_truth.json").read_text())
        baselines = load_baselines(d / b for b in gt.get("baselines", []))
        result = analyze((d / "dump.bin").read_bytes(), baselines=baselines)
        fired = {f.rule_id for f in result.findings}
        must, forbid = set(gt["must_fire"]), set(gt["must_not_fire"])
        for rule in must:
            s = res.per_rule.setdefault(rule, RuleScore())
            if rule in fired:
                s.tp += 1
            else:
                s.fn += 1
                res.violations.append(f"{d.name}: expected {rule} did not fire")
        for rule in forbid & fired:
            res.per_rule.setdefault(rule, RuleScore()).fp += 1
            res.violations.append(f"{d.name}: forbidden {rule} fired")
        if d.name == CLEAN_DEVICE:
            for f in result.findings:
                if SEVERITY_RANK[f.severity] >= SEVERITY_RANK["medium"] and f.rule_id not in must:
                    res.violations.append(
                        f"{d.name}: unexpected {f.severity} finding {f.rule_id} ({f.title})"
                    )
        res.devices.append(
            {
                "device": d.name,
                "must_fire": sorted(must),
                "fired": sorted(fired),
                "missed": sorted(must - fired),
                "forbidden_fired": sorted(forbid & fired),
                "finding_count": len(result.findings),
                "rule_errors": result.rule_errors,
            }
        )
        if result.rule_errors:
            res.violations.extend(f"{d.name}: rule error {e}" for e in result.rule_errors)
    overall = res.overall.recall
    if overall is None or overall < RECALL_GATE:
        res.violations.insert(0, f"overall recall {overall} < {RECALL_GATE}")
    # recall gate violation is only reported once even if per-device misses exist
    return res


def markdown_table(data: dict[str, Any]) -> str:
    def fmt(x: float | None) -> str:
        return "—" if x is None else f"{x:.2f}"

    lines = [
        "| Rule | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for rule, s in data["per_rule"].items():
        lines.append(
            f"| `{rule}` | {s['tp']} | {s['fp']} | {s['fn']} | {fmt(s['precision'])}"
            f" | {fmt(s['recall'])} | {fmt(s['f1'])} |"
        )
    o = data["overall"]
    lines.append(
        f"| **Overall** | **{o['tp']}** | **{o['fp']}** | **{o['fn']}** | **{fmt(o['precision'])}**"
        f" | **{fmt(o['recall'])}** | **{fmt(o['f1'])}** |"
    )
    gate = data["gate"]
    lines.append("")
    lines.append(
        f"Gate (recall ≥ {gate['recall_threshold']}, no forbidden rule, clean_control quiet): "
        + ("**PASS**" if gate["passed"] else "**FAIL**")
    )
    for v in gate["violations"]:
        lines.append(f"- {v}")
    return "\n".join(lines) + "\n"
