from __future__ import annotations

import pkgutil
import sqlite3
from pathlib import Path

import flashtrace.rules as rules_pkg
from flashtrace.pipeline import analyze, build_timeline, write_store
from flashtrace.rules import load_rules
from tests.fixtures.generator import (
    DumpSpec,
    app_desc,
    app_image,
    build_dump,
    otadata,
    otadata_entry,
)
from tools.corpus.nvs_writer import build_nvs


def dump_with_ts() -> bytes:
    rows = [
        ("sys", "namespace", "", ""),
        ("last_boot", "data", "u32", str(1767225600)),  # 2026-01-01T00:00:00Z
        ("fw_installed", "data", "string", "2026-02-03T04:05:06Z"),
        ("counter", "data", "u32", "12"),  # not a timestamp
    ]
    return build_dump(
        DumpSpec(
            apps={
                "ota_0": app_image(
                    desc=app_desc(version="1.0.0", date="Mar  4 2026", time="10:11:12")
                ),
                "ota_1": app_image(desc=app_desc(version="1.1.0"), seed=1),
            },
            otadata=otadata((otadata_entry(1, 2), otadata_entry(2, 2))),
            data={"nvs": build_nvs(rows, 0x4000)},
        )
    )


def test_rules_are_discovered_not_hardcoded() -> None:
    modules = [
        m.name for m in pkgutil.iter_modules(rules_pkg.__path__) if not m.name.startswith("_")
    ]
    assert len(load_rules()) == len(modules)


def test_finding_ids_are_stable_across_runs() -> None:
    d = dump_with_ts()
    a, b = analyze(d), analyze(d)
    assert [f.id for f in a.findings] == [f.id for f in b.findings] and a.findings


def test_timeline_records_sources() -> None:
    tl = build_timeline(analyze(dump_with_ts()).ctx)
    by_src = {t.ts_source: t for t in tl}
    app = next(t for s, t in by_src.items() if s.startswith("app_desc.date+time of ota_0"))
    assert app.value == "Mar  4 2026 10:11:12" and app.iso == "2026-03-04T10:11:12+00:00"
    assert app.trust == "device-reported, untrusted"
    nvs_u32 = next(t for s, t in by_src.items() if "sys/last_boot" in s)
    assert nvs_u32.iso == "2026-01-01T00:00:00+00:00"
    nvs_str = next(t for s, t in by_src.items() if "sys/fw_installed" in s)
    assert nvs_str.iso == "2026-02-03T04:05:06+00:00"
    assert not any("counter" in s for s in by_src)
    for t in tl:
        assert t.evidence.length > 0


def test_store_written(tmp_path: Path) -> None:
    r = analyze(dump_with_ts())
    db = tmp_path / "ev.sqlite"
    write_store(r, db)
    con = sqlite3.connect(db)
    assert con.execute("select count(*) from finding").fetchone()[0] == len(r.findings)
    assert con.execute("select count(*) from timeline").fetchone()[0] == len(r.timeline)
    srcs = [row[0] for row in con.execute("select ts_source from timeline")]
    assert all("device-reported" in s for s in srcs)
    assert con.execute("select count(*) from artifact where kind='partition'").fetchone()[0] >= 6
    con.close()


def test_chip_mismatch_is_an_anomaly() -> None:
    r = analyze(dump_with_ts(), chip="esp32s3")
    assert "CHIP_MISMATCH" in {
        f.detail.get("kind") for f in r.findings if f.rule_id == "PARSE.ANOMALY"
    }
    assert r.chip == "esp32s3"


def test_rule_errors_are_contained(monkeypatch: object) -> None:
    from flashtrace import rules

    def boom(ctx: object) -> list[object]:
        raise RuntimeError("bug")

    real = rules.load_rules()
    fake = dict(real)
    first = next(iter(fake))
    fake[first] = rules.Rule(first, "low", "t", "d", "", boom)  # type: ignore[arg-type]
    import flashtrace.pipeline as pl

    monkeypatch.setattr(pl, "load_rules", lambda: fake)  # type: ignore[attr-defined]
    r = pl.analyze(dump_with_ts())
    assert r.rule_errors and "RuntimeError" in r.rule_errors[0]
    assert r.findings  # other rules still ran


def test_hostile_timestamp_values() -> None:
    rows = [("s", "namespace", "", ""), ("t", "data", "u64", str(2**64 - 1))]
    d = build_dump(DumpSpec(apps={}, data={"nvs": build_nvs(rows, 0x4000)}))
    assert build_timeline(analyze(d).ctx) == []
