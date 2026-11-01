from __future__ import annotations

from flashtrace.diff import diff_dumps
from tests.fixtures.generator import (
    DumpSpec,
    app_desc,
    app_image,
    build_dump,
    otadata,
    otadata_entry,
)
from tools.corpus.nvs_writer import build_nvs
from tools.corpus.spiffs_writer import build_spiffs

ROWS_A = [
    ("app", "namespace", "", ""),
    ("mode", "data", "string", "a"),
    ("gone", "data", "u8", "1"),
]
ROWS_B = [("app", "namespace", "", ""), ("mode", "data", "string", "b"), ("new", "data", "u8", "2")]


def dev(
    rows: list[tuple[str, str, str, str]], v1: str, ota: int, files: list[tuple[str, bytes]]
) -> bytes:
    return build_dump(
        DumpSpec(
            apps={
                "ota_0": app_image(desc=app_desc(version="1.0.0")),
                "ota_1": app_image(desc=app_desc(version=v1), seed=1),
            },
            otadata=otadata((otadata_entry(1, 2), otadata_entry(2, ota))),
            data={"nvs": build_nvs(rows, 0x4000), "spiffs": build_spiffs(files, 0xF0000)},
        )
    )


def test_identical_dumps_have_no_diff() -> None:
    a = dev(ROWS_A, "1.1.0", 2, [("/f", b"x")])
    assert diff_dumps(a, a).findings == []


def test_diff_categories() -> None:
    a = dev(ROWS_A, "1.1.0", 2, [("/keep", b"same"), ("/old", b"o"), ("/chg", b"1")])
    b = dev(ROWS_B, "1.2.0", 1, [("/keep", b"same"), ("/new", b"n"), ("/chg", b"2")])
    res = diff_dumps(a, b)
    got = {(f.rule_id, f.title) for f in res.findings}
    rules = {r for r, _ in got}
    assert {
        "DIFF.PARTITION_CHANGED",
        "DIFF.APP_DESC",
        "DIFF.OTA_STATE",
        "DIFF.NVS_ADDED",
        "DIFF.NVS_REMOVED",
        "DIFF.NVS_CHANGED",
        "DIFF.FS_ADDED",
        "DIFF.FS_REMOVED",
        "DIFF.FS_CHANGED",
    } <= rules
    assert "DIFF.PARTITION_TABLE" not in rules
    chg = next(f for f in res.findings if f.rule_id == "DIFF.NVS_CHANGED")
    assert chg.detail["evidence_dumps"] == ["A", "B"] and len(chg.evidence) == 2
    app = next(f for f in res.findings if f.rule_id == "DIFF.APP_DESC")
    assert app.detail["changed"] == ["version"]
