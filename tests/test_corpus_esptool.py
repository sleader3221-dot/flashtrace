"""CI: esptool merge-bin must produce exactly the internal merge (runs with esptool)."""

from __future__ import annotations

from tests.conftest import require_module
from tools.corpus.generate import build_device, devices

require_module("esptool")


def test_esptool_merge_matches_internal_merge() -> None:
    for dev in devices()[:3]:
        via_esptool, tool = build_device(dev, use_esptool=True)
        internal, tool_i = build_device(dev, use_esptool=False)
        assert tool == "esptool" and tool_i == "internal"
        assert via_esptool == internal, dev.name
