import struct

from flashtrace.redact import mask, redact
from flashtrace.strings import extract_strings
from flashtrace.wifi import decode_wifi_blob, wifi_credentials
from tests.fixtures.nvs_cases import ROWS, SIZE, parse
from tools.corpus.nvs_writer import build_nvs


def test_decode_wifi_blob_layouts() -> None:
    assert decode_wifi_blob(struct.pack("<I", 4) + b"Home" + b"\x00" * 28, "ssid") == (
        b"Home",
        "length-prefixed",
    )
    assert decode_wifi_blob(b"secretpass" + b"\x00" * 54, "password") == (
        b"secretpass",
        "nul-terminated",
    )
    # implausible length prefix (too large) falls back to NUL-terminated
    assert decode_wifi_blob(struct.pack("<I", 999) + b"x", "ssid")[1] == "nul-terminated"
    assert decode_wifi_blob(b"", "ssid") == (b"", "nul-terminated")


def test_wifi_credentials_from_nvs() -> None:
    creds = wifi_credentials(parse(build_nvs(ROWS, SIZE)))
    assert len(creds) == 1
    c = creds[0]
    assert c.role == "sta" and c.ssid is not None and c.password is not None
    assert c.ssid.text == "FlashTraceLab" and c.ssid.layout == "length-prefixed"
    assert c.password.text == "example-wifi-pass" and c.password.layout == "nul-terminated"
    assert c.evidence


def test_wifi_string_values() -> None:
    rows = [
        ("nvs.net80211", "namespace", "", ""),
        ("ap.ssid", "data", "string", "SoftAP"),
        ("ap.passwd", "data", "string", "ap-pass-123"),
    ]
    creds = wifi_credentials(parse(build_nvs(rows, SIZE)))
    assert [(c.role, c.ssid.text if c.ssid else None) for c in creds] == [("ap", "SoftAP")]


def test_extract_strings_ascii_and_utf16() -> None:
    data = b"\x00\x01hello world\x01" + "wide-string".encode("utf-16le") + b"\xffab\x00"
    got = extract_strings(data, base_offset=0x1000)
    assert [(s.offset, s.text, s.encoding) for s in got] == [
        (0x1002, "hello world", "ascii"),
        (0x100E, "wide-string", "utf-16le"),
    ]
    assert got[1].length == 22
    assert extract_strings(data, min_len=20) == []
    assert [s.text for s in extract_strings(b"abcd", min_len=4)] == ["abcd"]


def test_redaction() -> None:
    assert mask("supersecret") == "su*******et"
    assert mask("abcd") == "****"
    assert redact(b"supersecret", reveal=True) == "supersecret"
    assert redact("supersecret", reveal=False) == "su*******et"
