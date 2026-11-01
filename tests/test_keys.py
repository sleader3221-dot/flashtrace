from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from flashtrace.commands import EXIT_FINDINGS, fallback_main
from flashtrace.keys import KeyMaterial
from flashtrace.pipeline import analyze
from tools.corpus.generate import (
    FLASH_KEY_ESP32,
    FLASH_KEY_XTS,
    NVS_KEY,
    SB_PUBKEY_PEM,
    build_device,
    devices,
)


def dump_of(name: str) -> bytes:
    return build_device(next(d for d in devices() if d.name == name), use_esptool=False)[0]


def rules(r: object) -> set[str]:
    return {f.rule_id for f in r.findings}  # type: ignore[attr-defined]


@pytest.fixture(scope="module")
def s3() -> bytes:
    return dump_of("esp32s3_encrypted_with_keys")


def test_encrypted_without_key_is_opaque(s3: bytes) -> None:
    r = analyze(s3)
    assert rules(r) == {"SEC.FLASH_ENCRYPTION_LIKELY"}
    assert r.ctx.decryption is None


def test_xts_flash_and_nvs_decryption(s3: bytes) -> None:
    r = analyze(s3, keys=KeyMaterial(flash_key=FLASH_KEY_XTS))
    dec = r.ctx.decryption
    assert dec is not None and dec.flash_scheme == "aes-xts"
    assert dec.nvs_partitions == ["nvs"] and dec.nvs_key_source == "partition nvs_keys"
    assert {"NVS.WIFI_CREDENTIALS", "SEC.FLASH_ENCRYPTION_LIKELY"} <= rules(r)
    assert "SEC.NO_FLASH_ENCRYPTION" not in rules(r)
    assert r.ctx.chip is not None and r.ctx.chip.chip == "esp32s3"
    assert r.ctx.dump_sha256 == dec.original_sha256  # identity of the evidence item
    wifi = next(f for f in r.findings if f.rule_id == "NVS.WIFI_CREDENTIALS")
    assert wifi.detail["ssid"] == "EncryptedLab-WiFi"


def test_nvs_key_supplied_directly(s3: bytes) -> None:
    r = analyze(s3, keys=KeyMaterial(flash_key=FLASH_KEY_XTS, nvs_key=NVS_KEY))
    assert r.ctx.decryption is not None and r.ctx.decryption.nvs_key_source == "supplied"
    assert "NVS.WIFI_CREDENTIALS" in rules(r)


def test_wrong_flash_key_is_reported(s3: bytes) -> None:
    r = analyze(s3, keys=KeyMaterial(flash_key=bytes(32)))
    assert "SEC.FLASH_ENCRYPTION_LIKELY" in rules(r)
    kinds = {f.detail.get("kind") for f in r.findings if f.rule_id == "PARSE.ANOMALY"}
    assert "KEY_DECRYPTION_FAILED" in kinds
    assert analyze(s3, keys=KeyMaterial(flash_key=b"short")).findings  # never crashes


def test_esp32_scheme_decryption() -> None:
    r = analyze(
        dump_of("esp32_encrypted_esp32_scheme"), keys=KeyMaterial(flash_key=FLASH_KEY_ESP32)
    )
    assert r.ctx.decryption is not None and r.ctx.decryption.flash_scheme == "esp32"
    assert {"SEC.API_KEY", "SEC.FLASH_ENCRYPTION_LIKELY"} <= rules(r)


def test_secure_boot_verification() -> None:
    d = dump_of("signed_ota_tampered")
    assert "IMG.SIGNATURE_INVALID" not in rules(analyze(d))  # inactive without a key
    r = analyze(d, sb_public_key=SB_PUBKEY_PEM)
    bad = [f for f in r.findings if f.rule_id == "IMG.SIGNATURE_INVALID"]
    assert [f.detail["partition"] for f in bad] == ["ota_1"]
    assert "image digest mismatch" in bad[0].detail["reasons"][0]
    assert any(c.verified for c in r.ctx.signature_checks["ota_0"])
    other = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    r2 = analyze(d, sb_public_key=other)
    assert {f.detail["partition"] for f in r2.findings if f.rule_id == "IMG.SIGNATURE_INVALID"} == {
        "ota_0",
        "ota_1",
    }
    r3 = analyze(d, sb_public_key=b"garbage")
    assert "SB_KEY_INVALID" in {f.detail.get("kind") for f in r3.findings}


def test_cli_key_options(s3: bytes, tmp_path: Path) -> None:
    (tmp_path / "d.bin").write_bytes(s3)
    (tmp_path / "k.bin").write_bytes(FLASH_KEY_XTS)
    code = fallback_main(
        [
            "analyze",
            str(tmp_path / "d.bin"),
            "--flash-key",
            str(tmp_path / "k.bin"),
            "--out",
            str(tmp_path / "r"),
            "--format",
            "json",
            "--format",
            "html",
        ]
    )
    assert code == EXIT_FINDINGS
    html = (tmp_path / "r" / "report.html").read_text()
    assert "Decrypted view" in html and "aes-xts" in html
