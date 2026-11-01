from pathlib import Path

from flashtrace.evidence import EvidenceStore
from flashtrace.model import Finding, make_evidence, make_finding

DUMP = b"\x00" * 64 + b"secret" + b"\xff" * 58
SHA = "d" * 64


def _finding(offset: int = 64) -> Finding:
    ev = make_evidence(DUMP, offset, 6, "nvs")
    return make_finding(
        "NVS.TEST",
        severity="high",
        title="t",
        detail={"key": "x", "value": "<redacted>"},
        evidence=(ev, make_evidence(DUMP, 0, 4, "nvs")),
        attck=("T0882",),
        confidence=0.9,
    )


def test_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "ev.sqlite"
    f = _finding()
    with EvidenceStore(db) as store:
        store.add_dump(SHA, len(DUMP), "esp32")
        store.add_finding(SHA, f)
        store.add_finding(SHA, f)  # idempotent
        store.add_timeline(SHA, "app_desc.date+time (ota_0)", "Jan  1 2026 12:00:00", f.id)
        art = store.add_artifact(SHA, "partition", "nvs", make_evidence(DUMP, 0, 128, "nvs"))
        assert art >= 1
    with EvidenceStore(db) as store:
        got = store.findings(SHA)
        assert got == [f]
        assert store.timeline(SHA) == [("app_desc.date+time (ota_0)", "Jan  1 2026 12:00:00", f.id)]
        assert store.artifacts(SHA)[0]["name"] == "nvs"
        assert store.findings("0" * 64) == []
