from __future__ import annotations

from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.nvs import NvsEntry
from flashtrace.redact import redact
from flashtrace.rules import rule
from flashtrace.secrets import SECRETISH_KEY, looks_like_secret_value
from flashtrace.wifi import PASS_KEYS, WIFI_NAMESPACE, decode_wifi_blob

RULE_ID = "NVS.DELETED_SECRET"


def _value_bytes(e: NvsEntry) -> bytes | None:
    v = e.value
    if isinstance(v, str):
        return v.encode()
    if isinstance(v, bytes):
        if e.namespace == WIFI_NAMESPACE and e.key in PASS_KEYS:
            return decode_wifi_blob(v, "password")[0]
        return v
    return None


def _meaningful(b: bytes) -> bool:
    stripped = b.strip(b"\x00\xff")
    return len(stripped) >= 4


@rule(
    RULE_ID,
    "high",
    "Deleted secret recoverable from NVS",
    "An ERASED NVS entry (bitmap 0b00) still holds a value whose key or content looks like a"
    " credential, token or key.",
    "Key-name heuristics can match non-secret config (e.g. 'auth_mode'); values that are all"
    " 0x00/0xFF or shorter than 4 bytes are ignored.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    for label, nvs in ctx.nvs.items():
        for e in nvs.recovered_deleted:
            vb = _value_bytes(e)
            if vb is None or not _meaningful(vb):
                continue
            by_key = SECRETISH_KEY.search(e.key) is not None
            by_value = looks_like_secret_value(vb)
            if not by_key and by_value is None:
                continue
            out.append(
                make_finding(
                    RULE_ID,
                    severity="high",
                    title=f"Deleted NVS value {e.qualified_key} is recoverable",
                    detail={
                        "nvs_partition": label,
                        "namespace": e.namespace,
                        "key": e.key,
                        "type": e.type_name,
                        "value": redact(vb, ctx.reveal_secrets),
                        "redacted": not ctx.reveal_secrets,
                        "value_sha256": e.value_sha256,
                        "matched_on": "key" if by_key else f"value:{by_value}",
                        "page": e.page,
                        "slot": e.slot,
                        "header_crc_ok": e.header_crc_ok,
                        "data_crc_ok": e.data_crc_ok,
                    },
                    evidence=e.evidence,
                    confidence=0.9 if e.data_crc_ok is not False else 0.6,
                )
            )
    return out
