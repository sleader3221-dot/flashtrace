"""Helpers to run registered rules against fixture dumps."""

from __future__ import annotations

from flashtrace.context import AnalysisContext, build_context
from flashtrace.model import Finding
from flashtrace.rules import load_rules

POSTURE_RULES = {"SEC.NO_FLASH_ENCRYPTION", "SEC.NO_SECURE_BOOT"}


def ctx_for(dump: bytes, **kw: object) -> AnalysisContext:
    return build_context(dump, **kw)  # type: ignore[arg-type]


def run_rule(rule_id: str, dump_or_ctx: bytes | AnalysisContext, **kw: object) -> list[Finding]:
    ctx = dump_or_ctx if isinstance(dump_or_ctx, AnalysisContext) else ctx_for(dump_or_ctx, **kw)
    return load_rules()[rule_id](ctx)


def run_all(dump_or_ctx: bytes | AnalysisContext, **kw: object) -> list[Finding]:
    ctx = dump_or_ctx if isinstance(dump_or_ctx, AnalysisContext) else ctx_for(dump_or_ctx, **kw)
    out: list[Finding] = []
    for r in load_rules().values():
        out.extend(r(ctx))
    return out
