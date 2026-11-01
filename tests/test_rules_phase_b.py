from __future__ import annotations

import hashlib
import random
import struct

import pytest

from flashtrace.rules import load_rules
from tests.fixtures.crypto_material import pem_private_key
from tests.fixtures.generator import (
    DEFAULT_LAYOUT,
    LAYOUT_WITH_COREDUMP,
    DumpSpec,
    Part,
    app_desc,
    app_image,
    build_dump,
    clean_nvs,
    otadata,
    otadata_entry,
    signed,
)
from tests.rule_helpers import POSTURE_RULES, run_all, run_rule
from tools.corpus.spiffs_writer import build_spiffs

PHASE_B = [
    "PT.MD5_MISMATCH",
    "PT.OVERLAP",
    "PT.OUT_OF_BOUNDS",
    "IMG.CHECKSUM_BAD",
    "IMG.SHA256_BAD",
    "IMG.NO_APP_DESC",
    "IMG.UNKNOWN_BUILD",
    "IMG.SLOT_DIVERGENCE",
    "OTA.ROLLBACK_OR_DOWNGRADE",
    "OTA.PENDING_VERIFY",
    "OTA.INVALID_ACTIVE",
    "FS.SUSPICIOUS_FILE",
    "CORE.PRESENT",
    "SEC.NO_FLASH_ENCRYPTION",
    "SEC.NO_SECURE_BOOT",
    "SEC.FLASH_ENCRYPTION_LIKELY",
    "PARSE.ANOMALY",
]


def mk(
    *,
    a0: bytes | None = None,
    a1: bytes | None = None,
    ota: tuple[bytes | None, bytes | None] | None = None,
    layout: tuple[Part, ...] = DEFAULT_LAYOUT,
    data: dict[str, bytes] | None = None,
    corrupt_md5: bool = False,
) -> bytes:
    return build_dump(
        DumpSpec(
            layout=layout,
            apps={
                "ota_0": a0 if a0 is not None else app_image(desc=app_desc(version="1.0.0")),
                "ota_1": a1
                if a1 is not None
                else app_image(desc=app_desc(version="1.1.0"), seed=1),
            },
            otadata=otadata(ota or (otadata_entry(1, 2), otadata_entry(2, 2))),
            data={"nvs": clean_nvs(), **(data or {})},
            corrupt_md5=corrupt_md5,
        )
    )


CLEAN = mk()


def fired(rule_id: str, dump: bytes, **kw: object) -> list[str]:
    return [f.title for f in run_rule(rule_id, dump, **kw)]


def test_registered() -> None:
    assert set(PHASE_B) <= set(load_rules())


@pytest.mark.parametrize("rule_id", sorted(set(PHASE_B) - POSTURE_RULES))
def test_silent_on_clean(rule_id: str) -> None:
    assert run_rule(rule_id, CLEAN) == []


def test_clean_only_posture_findings() -> None:
    assert {f.rule_id for f in run_all(CLEAN)} == POSTURE_RULES


def test_pt_rules() -> None:
    assert fired("PT.MD5_MISMATCH", mk(corrupt_md5=True))
    overlap = (*DEFAULT_LAYOUT[:-1], Part("spiffs", 1, 0x82, 0x300000, 0x100000))
    assert fired("PT.OVERLAP", mk(layout=overlap))
    oob = (*DEFAULT_LAYOUT[:-1], Part("spiffs", 1, 0x82, 0x310000, 0x200000))
    assert fired("PT.OUT_OF_BOUNDS", mk(layout=oob))
    assert not fired("PT.OVERLAP", mk(layout=oob))


def test_img_integrity_rules() -> None:
    assert fired("IMG.CHECKSUM_BAD", mk(a0=app_image(corrupt_checksum=True)))
    assert fired("IMG.SHA256_BAD", mk(a1=app_image(corrupt_sha256=True, seed=1)))
    assert fired("IMG.NO_APP_DESC", mk(a0=app_image(desc=b"\x00" * 256)))


def test_unknown_build() -> None:
    a0 = app_image(desc=app_desc(version="1.0.0"))
    a1 = app_image(desc=app_desc(version="1.1.0"), seed=1)
    dump = mk(a0=a0, a1=a1)
    h0, h1 = hashlib.sha256(a0).hexdigest(), hashlib.sha256(a1).hexdigest()
    assert fired("IMG.UNKNOWN_BUILD", dump) == []  # inactive without baselines
    [t] = fired("IMG.UNKNOWN_BUILD", dump, baselines=[h0])
    assert "ota_1" in t
    assert fired("IMG.UNKNOWN_BUILD", dump, baselines=[h0, h1]) == []


def test_slot_divergence() -> None:
    other = app_image(desc=app_desc(version="1.1.0", project_name="backdoor"), seed=1)
    [t] = fired("IMG.SLOT_DIVERGENCE", mk(a1=other))
    assert "project_name" in t
    idf = app_image(desc=app_desc(version="1.1.0", idf_ver="v4.4.1"), seed=1)
    assert fired("IMG.SLOT_DIVERGENCE", mk(a1=idf))
    jump = app_image(desc=app_desc(version="9.0.0"), seed=1)
    assert fired("IMG.SLOT_DIVERGENCE", mk(a1=jump))


def test_rollback_or_downgrade() -> None:
    a0 = app_image(desc=app_desc(version="1.0.0", secure_version=2))
    a1 = app_image(desc=app_desc(version="1.1.0", secure_version=1), seed=1)
    [t] = fired("OTA.ROLLBACK_OR_DOWNGRADE", mk(a0=a0, a1=a1))  # ota_1 active
    assert "secure_version 1 < 2" in t
    # active ota_0 (seq 3) running 1.0.0 while ota_1 holds 1.1.0
    rolled = mk(ota=(otadata_entry(3, 2), otadata_entry(2, 2)))
    [t] = fired("OTA.ROLLBACK_OR_DOWNGRADE", rolled)
    assert "version 1.0.0 < 1.1.0" in t


def test_pending_verify_and_invalid_active() -> None:
    assert fired("OTA.PENDING_VERIFY", mk(ota=(otadata_entry(1, 2), otadata_entry(2, 1))))
    assert not fired("OTA.INVALID_ACTIVE", mk(ota=(otadata_entry(1, 2), otadata_entry(2, 1))))
    latest_bad = mk(ota=(otadata_entry(1, 2), otadata_entry(2, 3)))
    [t] = fired("OTA.INVALID_ACTIVE", latest_bad)
    assert "INVALID" in t
    broken_active = mk(a1=app_image(corrupt_sha256=True, seed=1))
    assert any("no valid image" in t for t in fired("OTA.INVALID_ACTIVE", broken_active))


def _spiffs(files: list[tuple[str, bytes]]) -> bytes:
    return build_spiffs(files, 0xF0000)


def test_suspicious_file() -> None:
    dump = mk(
        data={
            "spiffs": _spiffs([("/certs/device.key", pem_private_key()), ("/i.html", b"<p>hi</p>")])
        }
    )
    findings = run_rule("FS.SUSPICIOUS_FILE", dump)
    assert [f.detail["path"] for f in findings] == ["/certs/device.key"]
    assert set(findings[0].detail["reasons"]) >= {"extension", "content:pem_private_key"}
    ev = findings[0].evidence
    assert b"".join(dump[e.offset : e.offset + e.length] for e in ev) == pem_private_key()
    elf = mk(data={"spiffs": _spiffs([("/upd", b"\x7fELF" + b"\x00" * 60)])})
    assert run_rule("FS.SUSPICIOUS_FILE", elf)[0].detail["reasons"] == ["elf"]
    benign = mk(data={"spiffs": _spiffs([("/index.html", b"<html>ok</html>")])})
    assert run_rule("FS.SUSPICIOUS_FILE", benign) == []


def test_unparseable_spiffs_gets_raw_sweep() -> None:
    junk = bytearray(random.Random(7).randbytes(0x2000))
    junk[99:121] = b"\x00AKIAIOSFODNN7EXAMPLE\x00"
    dump = mk(data={"spiffs": bytes(junk)})
    [f] = run_rule("SEC.API_KEY", dump)
    assert f.detail["region"] == "partition:spiffs"
    assert dump[f.evidence[0].offset : f.evidence[0].offset + 20] == b"AKIAIOSFODNN7EXAMPLE"
    assert "FS_SPIFFS_UNRECOGNISED" in {f.detail["kind"] for f in run_rule("PARSE.ANOMALY", dump)}


def test_core_present() -> None:
    core = struct.pack("<IIIIII", 0x800, 3, 4, 0x15C, 1, 3) + b"\x00" * 64
    [f] = run_rule("CORE.PRESENT", mk(layout=LAYOUT_WITH_COREDUMP, data={"coredump": core}))
    assert f.detail["format"] == "binary" and f.detail["tasks"] == 4
    assert run_rule("CORE.PRESENT", mk(layout=LAYOUT_WITH_COREDUMP)) == []


def test_posture_rules() -> None:
    assert fired("SEC.NO_FLASH_ENCRYPTION", CLEAN)
    assert fired("SEC.NO_SECURE_BOOT", CLEAN)
    sb = mk(a0=signed(app_image()), a1=signed(app_image(seed=1), 0x03))
    assert fired("SEC.NO_SECURE_BOOT", sb) == []


def test_encrypted_flash_simulated() -> None:
    enc = bytearray(CLEAN)
    enc[0x8000:0x310000] = random.Random(11).randbytes(0x310000 - 0x8000)
    findings = run_all(bytes(enc))
    assert [f.rule_id for f in findings] == ["SEC.FLASH_ENCRYPTION_LIKELY"]


def test_encrypted_flash_with_chance_table_magic() -> None:
    """Regression: ciphertext that happens to contain AA 50 at a 4 KB boundary."""
    enc = bytearray(CLEAN)
    enc[0x8000:0x310000] = random.Random(12).randbytes(0x310000 - 0x8000)
    for off in (0xA000, 0x20000, 0x200000):
        enc[off : off + 2] = b"\xaa\x50"
    findings = run_all(bytes(enc))
    assert [f.rule_id for f in findings] == ["SEC.FLASH_ENCRYPTION_LIKELY"]


def test_parse_anomaly() -> None:
    dump = mk(ota=(otadata_entry(1, 2), otadata_entry(2, 2, bad_crc=True)))
    kinds = {f.detail["kind"] for f in run_rule("PARSE.ANOMALY", dump)}
    assert kinds == {"OTA_CRC_BAD"}
    # anomalies owned by dedicated rules are not duplicated
    assert run_rule("PARSE.ANOMALY", mk(corrupt_md5=True)) == []
