"""Secret redaction: show the first and last 2 characters, mask the rest."""

from __future__ import annotations


def mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def redact(value: str | bytes, reveal: bool) -> str:
    text = value.decode("utf-8", errors="backslashreplace") if isinstance(value, bytes) else value
    return text if reveal else mask(text)
