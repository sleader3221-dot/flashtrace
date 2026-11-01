"""Detection rules. One module per rule; each registers itself with :func:`rule`.

Rules are discovered by importing every module in this package
(:func:`load_rules`), so the pipeline never hardcodes rule names.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, Severity

RuleFn = Callable[[AnalysisContext], list[Finding]]


Category = Literal["detection", "integrity", "posture", "diagnostic"]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: Severity
    title: str
    description: str
    false_positives: str
    fn: RuleFn
    category: Category = "detection"

    def __call__(self, ctx: AnalysisContext) -> list[Finding]:
        return self.fn(ctx)


REGISTRY: dict[str, Rule] = {}


def rule(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    false_positives: str = "",
    category: Category = "detection",
) -> Callable[[RuleFn], RuleFn]:
    """Register a rule. ``category="posture"`` marks configuration-weakness findings that
    are true of most plaintext dumps (excluded from the benchmark's clean-device gate)."""

    def deco(fn: RuleFn) -> RuleFn:
        if rule_id in REGISTRY and REGISTRY[rule_id].fn is not fn:
            raise ValueError(f"duplicate rule id {rule_id}")
        REGISTRY[rule_id] = Rule(
            rule_id, severity, title, description, false_positives, fn, category
        )
        return fn

    return deco


def load_rules() -> dict[str, Rule]:
    for mod in pkgutil.iter_modules(__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{__name__}.{mod.name}")
    return dict(sorted(REGISTRY.items()))
