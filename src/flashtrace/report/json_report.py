from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"


def write(data: dict[str, Any], path: Path) -> Path:
    path.write_text(dumps(data), encoding="utf-8")
    return path
