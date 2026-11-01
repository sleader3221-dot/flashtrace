import re
import tomllib
from pathlib import Path

import flashtrace

ROOT = Path(__file__).resolve().parents[1]


def test_versions_agree() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert meta["project"]["version"] == flashtrace.__version__
    assert re.search(
        rf"^## {re.escape(flashtrace.__version__)}\b", (ROOT / "CHANGELOG.md").read_text(), re.M
    )


def test_release_workflow_is_tag_only() -> None:
    import yaml

    wf = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    trigger = wf.get(True) or wf.get("on")  # YAML 1.1 parses `on` as True
    assert trigger == {"push": {"tags": ["v*.*.*"]}}
    assert wf["jobs"]["publish-pypi"]["permissions"] == {"id-token": "write"}
