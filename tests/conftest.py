from __future__ import annotations

import importlib
import os
from types import ModuleType

import pytest


def require_module(name: str) -> ModuleType:
    """Import an optional test dependency.

    Skips locally when missing; fails hard when FLASHTRACE_REQUIRE_TOOLS=1 (CI),
    so cross-checks against official tooling can never silently disappear.
    """
    try:
        return importlib.import_module(name)
    except ImportError:
        if os.environ.get("FLASHTRACE_REQUIRE_TOOLS") == "1":
            pytest.fail(f"required test dependency {name!r} is not installed", pytrace=False)
        pytest.skip(f"{name} not installed", allow_module_level=True)
