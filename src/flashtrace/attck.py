"""MITRE ATT&CK for ICS mapping, loaded from ``data/attck_ics_map.yaml``.

Only entries with ``review: false`` are attached to findings; everything else is a
proposal awaiting human review (see docs/rules.md).
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources

import yaml

from flashtrace.model import Finding

TECHNIQUE_RE = re.compile(r"^T0\d{3}$")  # ATT&CK for ICS IDs are T0800-T0899-style


@dataclass(frozen=True)
class Mapping:
    rule_id: str
    technique: str | None
    review: bool
    note: str

    @property
    def attached(self) -> tuple[str, ...]:
        return (self.technique,) if self.technique and not self.review else ()


@cache
def load_map() -> dict[str, Mapping]:
    text = resources.files("flashtrace").joinpath("data/attck_ics_map.yaml").read_text("utf-8")
    raw = yaml.safe_load(text) or {}
    out: dict[str, Mapping] = {}
    for rule_id, entry in raw.items():
        tech = entry.get("technique")
        if tech is not None and not TECHNIQUE_RE.match(str(tech)):
            raise ValueError(f"{rule_id}: {tech!r} is not an ATT&CK for ICS technique ID")
        out[str(rule_id)] = Mapping(
            str(rule_id),
            None if tech is None else str(tech),
            bool(entry["review"]),
            str(entry.get("note", "")),
        )
    return out


def enrich(findings: list[Finding]) -> list[Finding]:
    m = load_map()
    out: list[Finding] = []
    for f in findings:
        mapping = m.get(f.rule_id)
        extra = mapping.attached if mapping else ()
        merged = tuple(dict.fromkeys((*f.attck, *extra)))
        out.append(f if merged == f.attck else dataclasses.replace(f, attck=merged))
    return out
