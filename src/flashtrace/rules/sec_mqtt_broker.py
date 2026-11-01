from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding
from flashtrace.rules import rule
from flashtrace.rules._common import region_matches, secret_finding
from flashtrace.secrets import find_mqtt

RULE_ID = "SEC.MQTT_BROKER"


@rule(
    RULE_ID,
    "medium",
    "MQTT broker endpoint in flash",
    "An mqtt:// or mqtts:// URI, or a host:1883 / host:8883 endpoint, reveals the device's broker.",
    "Example/test broker strings shipped in libraries also match; deduplicated by value.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    seen: set[bytes] = set()
    for region, m, ev in region_matches(ctx, find_mqtt):
        if True and m.value in seen:
            continue
        seen.add(m.value)
        out.append(
            secret_finding(
                ctx,
                RULE_ID,
                "medium",
                f"MQTT endpoint in {region.label}",
                region,
                m,
                ev,
                is_secret=False,
            )
        )
    return out
