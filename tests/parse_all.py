"""Shared harness: run every parser over arbitrary bytes and check invariants."""

from __future__ import annotations

from flashtrace.appimage import find_signature_blocks, parse_app_image
from flashtrace.io import detect_chip, shannon_entropy
from flashtrace.model import Anomaly, anomaly_finding
from flashtrace.otadata import parse_otadata
from flashtrace.partition import (
    find_partition_table,
    layout_anomalies,
    parse_partition_table,
    partition_slice,
)

BASE = 0x10000


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

    for apps in (0, 1, 2, 16):
        ota = parse_otadata(data, BASE, apps)
        _check(ota.anomalies, BASE, n, data)
        if ota.active_slot is not None:
            assert 0 <= ota.active_slot < apps
