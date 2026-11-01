import hashlib

import pytest

from flashtrace.rules import load_rules
from tests.fixtures.crypto_material import der_cert, pem_cert, pem_private_key
from tests.fixtures.generator import (
    CLEAN_NVS_ROWS,
    DumpSpec,
    app_desc,
    app_image,
    build_dump,
    clean_dump,
    otadata,
    otadata_entry,
)
from tests.fixtures.nvs_cases import erase, parse
from tests.rule_helpers import POSTURE_RULES, run_all, run_rule
from tools.corpus.nvs_writer import build_nvs

PHASE_A = [
    "NVS.WIFI_CREDENTIALS",
    "NVS.DELETED_SECRET",
    "SEC.HARDCODED_CREDENTIAL",
    "SEC.API_KEY",
    "SEC.PRIVATE_KEY",
    "SEC.CERT",
    "SEC.MQTT_BROKER",
    "SEC.URL",
]
WIFI_ROWS = [
    ("nvs.net80211", "namespace", "", ""),
    ("sta.ssid", "data", "blob_sz_fill(32;0x00)", "LabNet"),
    ("sta.pswd", "data", "blob_fill(64;0x00)", "lab-pass-1234"),
]
TOKEN = "tok_EXAMPLE_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z"


def dump_with(*, rodata: bytes = b"", nvs: bytes | None = None) -> bytes:
    return build_dump(
        DumpSpec(
            apps={
                "ota_0": app_image(desc=app_desc(version="1.0.0"), rodata=rodata),
                "ota_1": app_image(desc=app_desc(version="1.1.0"), seed=1),
            },
            otadata=otadata((otadata_entry(1, 2), otadata_entry(2, 2))),
            data={"nvs": nvs if nvs is not None else build_nvs(CLEAN_NVS_ROWS, 0x4000)},
        )
    )


def assert_evidence_ok(dump: bytes, findings: list[object]) -> None:
    for f in findings:
        for ev in f.evidence:  # type: ignore[attr-defined]
            assert ev.sha256 == hashlib.sha256(dump[ev.offset : ev.offset + ev.length]).hexdigest()


def test_all_phase_a_rules_registered() -> None:
    assert set(PHASE_A) <= set(load_rules())


def test_clean_fixture_has_no_secret_findings() -> None:
    findings = run_all(clean_dump())
    bad = [
        f.rule_id
        for f in findings
        if f.rule_id.startswith(("SEC.", "NVS.")) and f.rule_id not in POSTURE_RULES
    ]
    assert bad == []


@pytest.mark.parametrize("rule_id", PHASE_A)
def test_rule_silent_on_clean(rule_id: str) -> None:
    assert run_rule(rule_id, clean_dump()) == []


def test_wifi_credentials_positive_and_redaction() -> None:
    dump = dump_with(nvs=build_nvs(CLEAN_NVS_ROWS + WIFI_ROWS, 0x4000))
    [f] = run_rule("NVS.WIFI_CREDENTIALS", dump)
    assert f.severity == "high" and f.detail["ssid"] == "LabNet"
    assert f.detail["password"] == "la*********34" and f.detail["redacted"]
    assert f.detail["password_sha256"] == hashlib.sha256(b"lab-pass-1234").hexdigest()
    assert_evidence_ok(dump, [f])
    [r] = run_rule("NVS.WIFI_CREDENTIALS", dump, reveal_secrets=True)
    assert r.detail["password"] == "lab-pass-1234" and r.id == f.id


def test_wifi_credentials_negative_ssid_only() -> None:
    rows = [
        *CLEAN_NVS_ROWS,
        ("nvs.net80211", "namespace", "", ""),
        ("sta.ssid", "data", "string", "Open"),
    ]
    assert run_rule("NVS.WIFI_CREDENTIALS", dump_with(nvs=build_nvs(rows, 0x4000))) == []


def test_deleted_secret_positive_and_negative() -> None:
    rows = [*CLEAN_NVS_ROWS, ("app", "namespace", "", ""), ("api_token", "data", "string", TOKEN)]
    nvs_bytes = build_nvs(rows, 0x4000)
    live = dump_with(nvs=nvs_bytes)
    assert run_rule("NVS.DELETED_SECRET", live) == []  # live, not deleted
    erased_nvs = erase(nvs_bytes, parse(nvs_bytes), "app", "api_token")
    dump = dump_with(nvs=erased_nvs)
    [f] = run_rule("NVS.DELETED_SECRET", dump)
    assert f.detail["key"] == "api_token" and f.detail["value"].startswith("to")
    assert "*" in f.detail["value"] and f.detail["matched_on"] == "key"
    assert_evidence_ok(dump, [f])
    # deleting a non-secret value does not fire
    benign = erase(nvs_bytes, parse(nvs_bytes), "storage", "device_name")
    assert run_rule("NVS.DELETED_SECRET", dump_with(nvs=benign)) == []


@pytest.mark.parametrize(
    ("rule_id", "planted", "kind"),
    [
        ("SEC.API_KEY", b"AKIAIOSFODNN7EXAMPLE", "aws_key_id"),
        ("SEC.API_KEY", TOKEN.encode(), "generic_token"),
        ("SEC.HARDCODED_CREDENTIAL", b'admin_password="Adm1n-Example!"', "credential_assignment"),
        ("SEC.MQTT_BROKER", b"mqtts://broker.example.com:8883", "mqtt_uri"),
        ("SEC.URL", b"https://ota.example.com/firmware.bin", "url"),
        ("SEC.CERT", None, "pem_cert"),
        ("SEC.CERT", b"DER", "der_cert"),
        ("SEC.PRIVATE_KEY", None, "pem_private_key"),
    ],
)
def test_sec_rules_positive(rule_id: str, planted: bytes | None, kind: str) -> None:
    if rule_id == "SEC.PRIVATE_KEY":
        planted = pem_private_key()
    elif rule_id == "SEC.CERT":
        planted = der_cert() if planted == b"DER" else pem_cert()
    assert planted is not None
    dump = dump_with(rodata=b"\x00" + planted + b"\x00")
    findings = [f for f in run_rule(rule_id, dump) if f.detail["kind"] == kind]
    assert len(findings) == 1, [f.detail for f in run_rule(rule_id, dump)]
    f = findings[0]
    assert f.detail["region"] == "app:ota_0"
    assert f.detail["value_sha256"] == hashlib.sha256(planted.strip()).hexdigest() or kind in (
        "credential_assignment",
        "url",
    )
    assert_evidence_ok(dump, findings)
    assert dump[f.evidence[0].offset : f.evidence[0].offset + 4] == planted.strip()[:4] or kind in (
        "credential_assignment",
    )


@pytest.mark.parametrize(
    ("rule_id", "near_miss"),
    [
        ("SEC.API_KEY", b"AKIAshort and 0123456789abcdef0123456789abcdef"),
        ("SEC.HARDCODED_CREDENTIAL", b"password=%s"),
        ("SEC.MQTT_BROKER", b"listen on port 1883"),
        ("SEC.URL", b"http:/not-a-url"),
        ("SEC.CERT", b"-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----"),
        ("SEC.PRIVATE_KEY", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"),
    ],
)
def test_sec_rules_negative(rule_id: str, near_miss: bytes) -> None:
    assert run_rule(rule_id, dump_with(rodata=near_miss)) == []


def test_secret_in_live_nvs_value_is_scanned() -> None:
    rows = [
        *CLEAN_NVS_ROWS,
        ("cloud", "namespace", "", ""),
        ("aws_id", "data", "string", "AKIAIOSFODNN7EXAMPLE"),
    ]
    dump = dump_with(nvs=build_nvs(rows, 0x4000))
    [f] = run_rule("SEC.API_KEY", dump)
    assert f.detail["region"] == "nvs:cloud/aws_id" and f.evidence[0].partition == "nvs"
    assert_evidence_ok(dump, [f])
