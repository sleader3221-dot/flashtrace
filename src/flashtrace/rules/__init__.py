"""Detection rules. One module per rule; each registers itself with :func:`rule`.

Rules are discovered by importing every module in this package
(:func:`load_rules`), so the pipeline never hardcodes rule names.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, Severity

RuleFn = Callable[[AnalysisContext], list[Finding]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: Severity
    title: str
    description: str
    false_positives: str
    fn: RuleFn

    def __call__(self, ctx: AnalysisContext) -> list[Finding]:
        return self.fn(ctx)


REGISTRY: dict[str, Rule] = {}


def rule(
    rule_id: str, severity: Severity, title: str, description: str, false_positives: str = ""
) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        if rule_id in REGISTRY and REGISTRY[rule_id].fn is not fn:
            raise ValueError(f"duplicate rule id {rule_id}")
        REGISTRY[rule_id] = Rule(rule_id, severity, title, description, false_positives, fn)
        return fn

    return deco


def load_rules() -> dict[str, Rule]:
    for mod in pkgutil.iter_modules(__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{__name__}.{mod.name}")
    return dict(sorted(REGISTRY.items()))
