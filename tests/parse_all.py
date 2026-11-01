"""Shared harness: run every parser over arbitrary bytes and check invariants."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from flashtrace import secrets
from flashtrace.appimage import find_signature_blocks, parse_app_image
from flashtrace.context import build_context
from flashtrace.coredump import parse_coredump
from flashtrace.crypto import parse_nvs_keys, verify_sbv2
from flashtrace.fs.littlefs import parse_littlefs
from flashtrace.fs.spiffs import parse_spiffs
from flashtrace.io import detect_chip, shannon_entropy
from flashtrace.keys import KeyMaterial, decrypt_view
from flashtrace.model import Anomaly, anomaly_finding
from flashtrace.nvs import parse_nvs
from flashtrace.otadata import parse_otadata
from flashtrace.partition import (
    find_partition_table,
    layout_anomalies,
    parse_partition_table,
    partition_slice,
)
from flashtrace.strings import extract_strings
from flashtrace.wifi import decode_wifi_blob

BASE = 0x10000
_SB_PRIV = ec.derive_private_key(12345, ec.SECP256R1())
_SB_KEY = _SB_PRIV.public_key()
_SB_PEM = _SB_KEY.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _check(anoms: tuple[Anomaly, ...], base: int, size: int, data: bytes) -> None:
    for a in anoms:
        assert base <= a.offset <= base + size, a
        assert a.length >= 0 and a.offset + a.length <= base + size, a
        # Every anomaly must be convertible into an evidence-backed finding.
        padded = b"\x00" * base + data
        f = anomaly_finding(padded, a, None)
        assert f.evidence[0].offset == a.offset and f.evidence[0].length == a.length


def run_all_parsers(data: bytes) -> None:
    n = len(data)
    assert 0.0 <= shannon_entropy(data) <= 8.0

    det = detect_chip(data)
    if det is not None:
        _check(det.anomalies, 0, n, data)

    img = parse_app_image(data, BASE)
    if img is not None:
        _check(img.anomalies, BASE, n, data)
        for s in img.segments:
            assert s.data_offset >= BASE and s.data_offset + s.data_len <= BASE + n
        if img.image_length is not None:
            assert img.image_length <= n
        for b in img.signature_blocks:
            assert b.offset >= BASE and b.offset + 1216 <= BASE + n
    find_signature_blocks(data, n // 2, BASE)

    table = parse_partition_table(data, BASE)
    _check(table.anomalies, BASE, n, data)
    assert table.length <= n
    layout_anomalies(table, n)
    for e in table.entries:
        part = partition_slice(data, e)
        parse_app_image(part, e.offset)
        parse_otadata(part, e.offset, len(table.ota_apps))
    find_partition_table(data)

    for keys in (False, True):
        nvs = parse_nvs(data, BASE, "nvs", nvs_keys_present=keys)
        _check(nvs.anomalies, BASE, n, data)
        for e in (*nvs.entries, *nvs.recovered_deleted):
            for ev in e.evidence:
                assert ev.offset >= BASE and ev.offset + ev.length <= BASE + n
    for s in extract_strings(data, BASE, 4):
        assert s.offset >= BASE and s.offset + s.length <= BASE + n
    for fn in (
        secrets.find_private_keys,
        secrets.find_certificates,
        secrets.find_aws_keys,
        secrets.find_generic_tokens,
        secrets.find_mqtt,
        secrets.find_urls,
        secrets.find_credentials,
    ):
        for m in fn(data):
            assert m.rel >= 0 and m.rel + m.length <= n
    for fs in (parse_spiffs(data, BASE, "fs"), parse_littlefs(data, BASE, "fs")):
        _check(fs.anomalies, BASE, n, data)
        for f in fs.files:
            for seg in f.segments:
                assert seg.abs_offset >= BASE and seg.abs_offset + seg.length <= BASE + n
    _check(parse_coredump(data, BASE, "core").anomalies, BASE, n, data)
    decode_wifi_blob(data, "ssid")
    decode_wifi_blob(data, "password")
    build_context(data)
    parse_nvs_keys(data)
    for r in verify_sbv2(data + b"\xff" * (-len(data) % 4096), _SB_KEY):
        assert not r.verified
    view, _info = decrypt_view(data, KeyMaterial(flash_key=bytes(32), nvs_key=bytes(64)))
    assert len(view) == n
    build_context(data, keys=KeyMaterial(flash_key=bytes(range(32))), sb_public_key=_SB_PEM)

    for apps in (0, 1, 2, 16):
        ota = parse_otadata(data, BASE, apps)
        _check(ota.anomalies, BASE, n, data)
        if ota.active_slot is not None:
            assert 0 <= ota.active_slot < apps
