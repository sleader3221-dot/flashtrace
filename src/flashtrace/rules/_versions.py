"""Version helpers shared by OTA/slot rules."""

from __future__ import annotations

import re

SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


def semver(text: str) -> tuple[int, int, int] | None:
    m = SEMVER.match(text.strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None
