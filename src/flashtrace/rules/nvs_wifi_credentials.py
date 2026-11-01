from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding, sha256_hex
from flashtrace.redact import redact
from flashtrace.rules import rule
from flashtrace.wifi import wifi_credentials

RULE_ID = "NVS.WIFI_CREDENTIALS"


@rule(
    RULE_ID,
    "high",
    "Wi-Fi credentials stored in NVS",
    "A station or soft-AP passphrase is present in the live nvs.net80211 namespace.",
    "Open networks have no passphrase and do not fire. Factory test credentials still fire.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    for label, nvs in ctx.nvs.items():
        if nvs.encrypted:
            continue
        for cred in wifi_credentials(nvs):
            if cred.password is None:
                continue
            detail = {
                "nvs_partition": label,
                "role": cred.role,
                "ssid": cred.ssid.text if cred.ssid else None,
                "password": redact(cred.password.value, ctx.reveal_secrets),
                "redacted": not ctx.reveal_secrets,
                "password_sha256": sha256_hex(cred.password.value),
                "password_layout": cred.password.layout,
                "ssid_layout": cred.ssid.layout if cred.ssid else None,
            }
            out.append(
                make_finding(
                    RULE_ID,
                    severity="high",
                    title=f"Wi-Fi {cred.role.upper()} credentials in NVS"
                    + (f" (SSID {cred.ssid.text!r})" if cred.ssid else ""),
                    detail=detail,
                    evidence=cred.evidence,
                    confidence=0.95,
                )
            )
    return out
