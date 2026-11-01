from __future__ import annotations

from flashtrace import secrets
from flashtrace.appimage import parse_app_image
from flashtrace.context import AnalysisContext
from flashtrace.model import Finding, make_finding
from flashtrace.rules import rule

RULE_ID = "FS.SUSPICIOUS_FILE"
SUSPICIOUS_EXT = (".pem", ".key", ".der", ".sh", ".py", ".lua", ".p12", ".pfx", ".crt")
SEC_DETECTORS = (
    secrets.find_private_keys,
    secrets.find_certificates,
    secrets.find_aws_keys,
    secrets.find_generic_tokens,
    secrets.find_credentials,
    secrets.find_mqtt,
    secrets.find_urls,
)


@rule(
    RULE_ID,
    "medium",
    "Suspicious file in filesystem",
    "A SPIFFS/LittleFS file is a key/cert/script by extension (.pem .key .der .crt .p12 .pfx"
    " .sh .py .lua), is an executable (ELF or ESP image), or its content triggers a SEC.* "
    "detector.",
    "Web UIs legitimately ship URLs and CA certificates; review the reasons list.",
)
def check(ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    for label, fs in ctx.filesystems.items():
        whole = ctx.ev(fs.offset, fs.size, label)
        for f in fs.files:
            reasons: list[str] = []
            if f.path.lower().endswith(SUSPICIOUS_EXT):
                reasons.append("extension")
            if f.data.startswith(b"\x7fELF"):
                reasons.append("elf")
            elif f.data[:1] == b"\xe9":
                img = parse_app_image(f.data)
                if img is not None and img.header is not None and img.header.chip is not None:
                    reasons.append("esp_image")
            for det in SEC_DETECTORS:
                m = next(iter(det(f.data)), None)
                if m is not None:
                    reasons.append(f"content:{m.kind}")
            if not reasons:
                continue
            ev = tuple(ctx.ev(s.abs_offset, s.length, label) for s in f.segments) or (whole,)
            out.append(
                make_finding(
                    RULE_ID,
                    severity="medium",
                    title=f"Suspicious file {f.path} in {label}",
                    detail={
                        "partition": label,
                        "fs": fs.fs_type,
                        "path": f.path,
                        "size": f.size,
                        "sha256": f.sha256,
                        "reasons": reasons,
                        "located": f.located,
                    },
                    evidence=ev,
                    confidence=0.9 if f.located else 0.7,
                )
            )
    return out
