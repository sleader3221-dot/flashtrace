"""Read-only filesystem parsers (SPIFFS, LittleFS) with a common result model."""

from __future__ import annotations

from dataclasses import dataclass, field

from flashtrace.model import Anomaly, Segment, sha256_hex

MAX_FILES = 4096
MAX_TOTAL_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class FsFile:
    path: str
    size: int
    data: bytes
    segments: tuple[Segment, ...]  # where the bytes live in the dump (may be empty)
    located: bool  # True when ``segments`` cover the whole content exactly
    complete: bool = True

    @property
    def sha256(self) -> str:
        return sha256_hex(self.data)


@dataclass(frozen=True)
class FsListing:
    fs_type: str  # "spiffs" | "littlefs"
    partition: str | None
    offset: int
    size: int
    mounted: bool
    detail: str  # e.g. "block_size=4096" or why it did not mount
    files: tuple[FsFile, ...] = ()
    directories: tuple[str, ...] = ()
    anomalies: tuple[Anomaly, ...] = field(default_factory=tuple)
