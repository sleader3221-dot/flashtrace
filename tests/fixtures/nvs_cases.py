"""NVS CSV fixtures shared by unit tests and the official-tool cross-check."""

from __future__ import annotations

import base64

from flashtrace.nvs import NvsPartition, parse_nvs

Row = tuple[str, str, str, str]

INTS: list[Row] = [
    ("u8k", "data", "u8", "200"),
    ("i8k", "data", "i8", "-5"),
    ("u16k", "data", "u16", "65535"),
    ("i16k", "data", "i16", "-1234"),
    ("u32k", "data", "u32", "4000000000"),
    ("i32k", "data", "i32", "-70000"),
    ("u64k", "data", "u64", "18446744073709551615"),
    ("i64k", "data", "i64", "-9000000000000"),
]
BIG_BLOB = bytes(range(256)) * 30  # 7680 bytes -> chunked across pages
ROWS: list[Row] = [
    ("storage", "namespace", "", ""),
    *INTS,
    ("short", "data", "string", "hi"),
    ("long", "data", "string", "L" * 1500),  # multi-span string
    ("small_blob", "data", "hex2bin", "deadbeef"),
    ("big_blob", "data", "base64", base64.b64encode(BIG_BLOB).decode()),
    ("nvs.net80211", "namespace", "", ""),
    ("sta.ssid", "data", "blob_sz_fill(32;0x00)", "FlashTraceLab"),
    ("sta.pswd", "data", "blob_fill(64;0x00)", "example-wifi-pass"),
    ("app", "namespace", "", ""),
    ("api_token", "data", "string", "tok_EXAMPLE_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z"),
    ("boot_count", "data", "u32", "42"),
]
EXPECTED: dict[tuple[str, str], int | str | bytes] = {
    ("storage", "u8k"): 200,
    ("storage", "i8k"): -5,
    ("storage", "u16k"): 65535,
    ("storage", "i16k"): -1234,
    ("storage", "u32k"): 4000000000,
    ("storage", "i32k"): -70000,
    ("storage", "u64k"): 18446744073709551615,
    ("storage", "i64k"): -9000000000000,
    ("storage", "short"): "hi",
    ("storage", "long"): "L" * 1500,
    ("storage", "small_blob"): bytes.fromhex("deadbeef"),
    ("storage", "big_blob"): BIG_BLOB,
    ("nvs.net80211", "sta.ssid"): b"\x0d\x00\x00\x00FlashTraceLab" + b"\x00" * 19,
    ("nvs.net80211", "sta.pswd"): b"example-wifi-pass" + b"\x00" * 47,
    ("app", "api_token"): "tok_EXAMPLE_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z",
    ("app", "boot_count"): 42,
}
SIZE = 0x6000


def values(nvs: NvsPartition) -> dict[tuple[str, str], int | str | bytes]:
    return {(e.namespace or "", e.key): e.value for e in nvs.entries if e.value is not None}


def erase(data: bytes, nvs: NvsPartition, namespace: str, key: str) -> bytes:
    """Flip bitmap state 0b10 -> 0b00 for every slot of an item (incl. blob chunks).

    Mirrors what nvs_flash does on erase; nothing else (CRCs, data) is touched.
    """
    buf = bytearray(data)
    targets = [e for e in nvs.entries if e.namespace == namespace and e.key == key]
    assert targets, (namespace, key)
    slots: list[tuple[int, int, int]] = []
    for e in targets:
        slots.append((e.page, e.slot, e.span))
        for ev in e.evidence[1:]:
            rel = ev.offset - nvs.offset
            page, off = divmod(rel, 4096)
            if off >= 64 and (off - 64) % 32 == 0 and ev.length % 32 == 0 and ev.length:
                slots.append((page, (off - 64) // 32, ev.length // 32))
    for page, slot, span in slots:
        for s in range(slot, slot + span):
            bit = s * 2
            buf[page * 4096 + 32 + bit // 8] &= ~(0b11 << (bit % 8)) & 0xFF
    return bytes(buf)


def parse(data: bytes, **kw: bool) -> NvsPartition:
    return parse_nvs(data, 0x9000, "nvs", **kw)
