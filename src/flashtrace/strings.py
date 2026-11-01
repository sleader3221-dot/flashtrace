"""Printable-string extraction (ASCII and UTF-16LE) that keeps absolute offsets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from flashtrace.model import ByteSource

DEFAULT_MIN_LEN = 6
_PRINTABLE = rb"\t\x20-\x7e"


@dataclass(frozen=True)
class ExtractedString:
    offset: int  # absolute offset of the first byte
    length: int  # length in BYTES (UTF-16LE strings are 2 bytes per char)
    text: str
    encoding: Literal["ascii", "utf-16le"]


def extract_strings(
    data: ByteSource, base_offset: int = 0, min_len: int = DEFAULT_MIN_LEN
) -> list[ExtractedString]:
    min_len = max(1, min_len)
    raw = bytes(data)
    out: list[ExtractedString] = []
    for m in re.finditer(rb"[%s]{%d,}" % (_PRINTABLE, min_len), raw):
        out.append(
            ExtractedString(
                base_offset + m.start(), m.end() - m.start(), m.group().decode(), "ascii"
            )
        )
    for m in re.finditer(rb"(?:[%s]\x00){%d,}" % (_PRINTABLE, min_len), raw):
        out.append(
            ExtractedString(
                base_offset + m.start(),
                m.end() - m.start(),
                m.group().decode("utf-16le"),
                "utf-16le",
            )
        )
    out.sort(key=lambda s: (s.offset, s.encoding))
    return out
