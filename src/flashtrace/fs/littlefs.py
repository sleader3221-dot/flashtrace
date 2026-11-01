"""Read-only LittleFS listing via littlefs-python 0.19.0.

API confirmed from littlefs-python v0.19.0 source: ``littlefs.LittleFS(context=
UserContext(buffer=bytearray), mount=False, block_size=, block_count=)``,
``.mount()``, ``.walk(top)``, ``.open(path, "rb")``; errors derive from
``littlefs.errors.LittleFSError``. NOTE: ``LittleFS(mount=True)`` FORMATS the
buffer when mounting fails, so FlashTrace always passes ``mount=False`` and works
on a private copy of the bytes.

littlefs-python does not expose on-flash block addresses, so a file's dump offset
is found by searching the partition for its content; files that are not stored
contiguously (or are shorter than 16 bytes) are reported with ``located=False``.
"""

from __future__ import annotations

from typing import Any

from flashtrace.fs import MAX_FILES, MAX_TOTAL_BYTES, FsFile, FsListing
from flashtrace.model import Anomaly, ByteSource, Segment

BLOCK_SIZES = (4096, 512, 1024, 2048, 8192)
MIN_LOCATE_LEN = 16


def _unavailable(base: int, size: int, partition: str | None, why: str) -> FsListing:
    return FsListing(
        "littlefs",
        partition,
        base,
        size,
        False,
        why,
        anomalies=(
            Anomaly(
                "FS_LITTLEFS_UNMOUNTABLE",
                f"LittleFS partition could not be mounted: {why}",
                base,
                size,
                {"partition": partition},
            ),
        ),
    )


def _mount(lfs_mod: Any, raw: bytes, block_size: int) -> Any:
    ctx = lfs_mod.UserContext(buffer=bytearray(raw))
    fs = lfs_mod.LittleFS(
        context=ctx, mount=False, block_size=block_size, block_count=len(raw) // block_size
    )
    fs.mount()
    return fs


def parse_littlefs(
    data: ByteSource, base_offset: int = 0, partition: str | None = None
) -> FsListing:
    raw = bytes(data)
    try:
        import littlefs as lfs_mod  # noqa: PLC0415 - optional dependency
    except ImportError:
        return _unavailable(base_offset, len(raw), partition, "littlefs-python is not installed")
    fs: Any = None
    used_bs = 0
    for bs in BLOCK_SIZES:
        if len(raw) < 2 * bs or len(raw) % bs:
            continue
        try:
            fs = _mount(lfs_mod, raw, bs)
            used_bs = bs
            break
        except Exception:  # noqa: S112 - any mount failure means "try the next size"
            continue
    if fs is None:
        return _unavailable(base_offset, len(raw), partition, f"no block size in {BLOCK_SIZES}")
    files: list[FsFile] = []
    dirs: list[str] = []
    anomalies: list[Anomaly] = []
    total = 0
    try:
        for root, dnames, fnames in fs.walk("/"):
            for d in dnames:
                dirs.append("/" + "/".join(x for x in (root.strip("/"), d) if x))
            for f in fnames:
                path = "/" + "/".join(x for x in (root.strip("/"), f) if x)
                if len(files) >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                    anomalies.append(
                        Anomaly("FS_TOO_MANY_FILES", "file listing truncated", base_offset, 0)
                    )
                    raise StopIteration
                with fs.open(path, "rb") as fh:
                    content = bytes(fh.read(MAX_TOTAL_BYTES - total))
                total += len(content)
                files.append(_locate(raw, base_offset, path, content))
    except StopIteration:
        pass
    except Exception as exc:  # corrupted metadata mid-walk: keep what we have
        anomalies.append(
            Anomaly(
                "FS_LITTLEFS_WALK_ERROR",
                f"LittleFS walk aborted: {type(exc).__name__}",
                base_offset,
                len(raw),
            )
        )
    return FsListing(
        "littlefs",
        partition,
        base_offset,
        len(raw),
        True,
        f"block_size={used_bs}",
        tuple(files),
        tuple(dirs),
        tuple(anomalies),
    )


def _locate(raw: bytes, base: int, path: str, content: bytes) -> FsFile:
    if len(content) >= MIN_LOCATE_LEN:
        idx = raw.find(content)
        if idx >= 0:
            return FsFile(
                path, len(content), content, (Segment(0, base + idx, len(content)),), True
            )
    return FsFile(path, len(content), content, (), False)
