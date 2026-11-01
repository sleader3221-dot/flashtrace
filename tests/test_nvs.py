import hashlib
import random
import struct
import zlib

import pytest

from flashtrace.nvs import parse_nvs
from tests.fixtures.nvs_cases import EXPECTED, ROWS, SIZE, erase, parse, values
from tools.corpus.nvs_writer import build_nvs


@pytest.fixture(scope="module")
def image() -> bytes:
    return build_nvs(ROWS, SIZE)


def kinds(nvs: object) -> list[str]:
    return [a.kind for a in nvs.anomalies]  # type: ignore[attr-defined]


def test_recovers_every_written_value(image: bytes) -> None:
    nvs = parse(image)
    assert not nvs.encrypted and nvs.anomalies == ()
    got = values(nvs)
    for k, v in EXPECTED.items():
        assert got[k] == v, k
    assert nvs.namespaces == {1: "storage", 2: "nvs.net80211", 3: "app"}
    assert nvs.recovered_deleted == ()
    big = nvs.get("storage", "big_blob")[0]
    assert big.type_name == "BLOB_IDX" and len(big.chunks) >= 2 and big.complete
    long = nvs.get("storage", "long")[0]
    assert long.type_name == "STR" and long.span == 1 + (1501 + 31) // 32
    assert {p.state_name for p in nvs.pages} <= {"ACTIVE", "FULL"}
    assert all(p.header_crc_ok for p in nvs.pages)


def test_every_value_carries_exact_evidence(image: bytes) -> None:
    nvs = parse(image)
    for e in nvs.entries:
        assert e.evidence and e.payload
        for ev in e.evidence:
            rel = ev.offset - 0x9000
            assert ev.sha256 == hashlib.sha256(image[rel : rel + ev.length]).hexdigest()
        base = 0x9000
        payload = b"".join(image[p.offset - base : p.offset - base + p.length] for p in e.payload)
        assert hashlib.sha256(payload).hexdigest() == e.value_sha256 or isinstance(e.value, int)


@pytest.mark.parametrize(
    ("ns", "key"),
    [("app", "api_token"), ("storage", "big_blob"), ("storage", "u32k"), ("storage", "long")],
)
def test_erased_entries_are_recovered(image: bytes, ns: str, key: str) -> None:
    erased = erase(image, parse(image), ns, key)
    nvs = parse(erased)
    assert (ns, key) not in values(nvs)
    rec = [e for e in nvs.recovered_deleted if (e.namespace, e.key) == (ns, key)]
    assert len(rec) == 1
    assert rec[0].status == "erased" and rec[0].value == EXPECTED[(ns, key)]
    assert rec[0].offset == parse(image).get(ns, key)[0].offset
    # everything else is untouched
    before = values(parse(image))
    del before[(ns, key)]
    assert values(nvs) == before


def test_legacy_blob_and_crc_mismatch() -> None:
    page = bytearray(b"\xff" * 4096)
    hdr = bytearray(b"\xff" * 32)
    struct.pack_into("<IIB", hdr, 0, 0xFFFFFFFE, 0, 0xFF)
    struct.pack_into("<I", hdr, 28, zlib.crc32(bytes(hdr[4:28]), 0xFFFFFFFF))
    page[0:32] = hdr
    ns = bytearray(b"\xff" * 32)
    ns[0:4] = bytes([0, 0x01, 1, 0xFF])
    ns[8:24] = b"legacy".ljust(16, b"\x00")
    ns[24] = 1
    struct.pack_into("<I", ns, 4, zlib.crc32(bytes(ns[0:4] + ns[8:32]), 0xFFFFFFFF))
    payload = b"legacy-blob-bytes"
    e = bytearray(b"\xff" * 32)
    e[0:4] = bytes([1, 0x41, 2, 0xFF])
    e[8:24] = b"lb".ljust(16, b"\x00")
    struct.pack_into("<H", e, 24, len(payload))
    struct.pack_into("<I", e, 28, zlib.crc32(payload, 0xFFFFFFFF))
    struct.pack_into("<I", e, 4, zlib.crc32(bytes(e[0:4] + e[8:32]), 0xFFFFFFFF))
    page[64:96], page[96 : 96 + len(payload)], page[128:160] = ns, payload, e
    page[160 : 160 + len(payload)] = payload
    bitmap = bytearray(b"\xff" * 32)
    for s in range(4):  # slot 0 ns, slot1 junk payload (written), slot 2 blob, slot 3 payload
        bitmap[s * 2 // 8] &= ~(1 << (s * 2 % 8)) & 0xFF
    page[32:64] = bitmap
    data = bytes(page) + b"\xff" * 8192
    nvs = parse_nvs(data, 0, "nvs")
    lb = [x for x in nvs.entries if x.key == "lb"]
    assert lb and lb[0].type_name == "BLOB" and lb[0].value == payload

    bad = bytearray(data)
    bad[160] ^= 0xFF  # corrupt payload -> data CRC mismatch, still no crash
    nvs = parse_nvs(bytes(bad), 0, "nvs")
    assert "NVS_DATA_CRC" in kinds(nvs)
    bad[128 + 10] ^= 0xFF  # corrupt the key -> header CRC mismatch
    nvs = parse_nvs(bytes(bad), 0, "nvs")
    assert "NVS_ENTRY_CRC" in kinds(nvs)


def test_page_header_crc_and_state(image: bytes) -> None:
    bad = bytearray(image)
    bad[8] = 0x01  # version byte is covered by the header CRC
    assert "NVS_PAGE_HEADER_CRC" in kinds(parse(bytes(bad)))
    bad = bytearray(image)
    bad[0:4] = b"\x00\x00\x00\x00"  # INVALID page state
    nvs = parse(bytes(bad))
    assert "NVS_PAGE_STATE" in kinds(nvs)


def test_encrypted_detection(image: bytes) -> None:
    rnd = random.Random(SIZE).randbytes(SIZE)
    nvs = parse(rnd)
    assert nvs.encrypted and nvs.entries == () and "entropy" in (nvs.encryption_reason or "")
    # nvs_keys present + every written entry's CRC broken (as with XTS-encrypted entries)
    enc = bytearray(image)
    for p in range(SIZE // 4096):
        enc[p * 4096 + 64 : (p + 1) * 4096] = random.Random(4096 - 64).randbytes(4096 - 64)
    nvs = parse(bytes(enc), nvs_keys_present=True)
    assert nvs.encrypted and "nvs_keys" in (nvs.encryption_reason or "")
    assert not parse(image, nvs_keys_present=True).encrypted


def test_blank_and_tiny_inputs() -> None:
    nvs = parse(b"\xff" * SIZE)
    assert nvs.entries == () and nvs.pages == () and nvs.anomalies == ()
    assert parse(b"").entries == ()
    assert "NVS_PARTIAL_PAGE" in kinds(parse(b"\xff" * 100))
