"""Wi-Fi credential extraction from the ``nvs.net80211`` namespace.

Key names were confirmed from the ESP-IDF Wi-Fi driver binary
(``espressif/esp32-wifi-lib`` ``esp32/libnet80211.a``, strings ``nvs.net80211``,
``sta.ssid``, ``sta.pswd``, ``ap.ssid``, ``ap.passwd``, ``sta.pmk``, ...) and from
esp-idf-nvs-partition-gen 0.2.0, which special-cases ``sta.ssid``/``sta.pswd``
and offers ``blob_sz_fill`` (u32 length + bytes + padding) for them.

The exact on-device blob layout is closed source, so values are decoded
defensively: a u32 little-endian length prefix is used when it is plausible
(1..32 for SSIDs, 1..64 for passphrases and fits the blob), otherwise the value
is read up to the first NUL. See CLAUDE.md "Wi-Fi" for the open questions.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from flashtrace.model import Evidence
from flashtrace.nvs import NvsEntry, NvsPartition

WIFI_NAMESPACE = "nvs.net80211"
SSID_KEYS = {"sta.ssid": "sta", "ap.ssid": "ap"}
PASS_KEYS = {"sta.pswd": "sta", "ap.passwd": "ap"}
MAX_LEN = {"ssid": 32, "password": 64}


@dataclass(frozen=True)
class WifiValue:
    role: str  # "sta" | "ap"
    field: str  # "ssid" | "password"
    value: bytes
    layout: str  # "length-prefixed" | "nul-terminated" | "string"
    entry: NvsEntry

    @property
    def text(self) -> str:
        return self.value.decode("utf-8", errors="backslashreplace")


@dataclass(frozen=True)
class WifiCredential:
    role: str
    ssid: WifiValue | None
    password: WifiValue | None

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        out: list[Evidence] = []
        for v in (self.ssid, self.password):
            if v is not None:
                out.extend(v.entry.evidence)
        return tuple(out)


def decode_wifi_blob(raw: bytes, field: str) -> tuple[bytes, str]:
    limit = MAX_LEN[field]
    if len(raw) >= 5:
        (n,) = struct.unpack_from("<I", raw, 0)
        if 1 <= n <= min(limit, len(raw) - 4) and all(b == 0 for b in raw[4 + n : 4 + limit]):
            return raw[4 : 4 + n], "length-prefixed"
    return raw[:limit].split(b"\x00", 1)[0], "nul-terminated"


def _value(entry: NvsEntry, role: str, field: str) -> WifiValue | None:
    v = entry.value
    if isinstance(v, str):
        return WifiValue(role, field, v.encode(), "string", entry) if v else None
    if isinstance(v, bytes):
        data, layout = decode_wifi_blob(v, field)
        return WifiValue(role, field, data, layout, entry) if data else None
    return None


def wifi_values(entries: tuple[NvsEntry, ...]) -> list[WifiValue]:
    out: list[WifiValue] = []
    for e in entries:
        if e.namespace != WIFI_NAMESPACE:
            continue
        if e.key in SSID_KEYS:
            w = _value(e, SSID_KEYS[e.key], "ssid")
        elif e.key in PASS_KEYS:
            w = _value(e, PASS_KEYS[e.key], "password")
        else:
            continue
        if w is not None:
            out.append(w)
    return out


def wifi_credentials(nvs: NvsPartition) -> list[WifiCredential]:
    """Live station / soft-AP credentials (latest value per key wins)."""
    latest: dict[tuple[str, str], WifiValue] = {}
    for w in wifi_values(nvs.entries):
        latest[(w.role, w.field)] = w
    creds: list[WifiCredential] = []
    for role in ("sta", "ap"):
        ssid, pw = latest.get((role, "ssid")), latest.get((role, "password"))
        if ssid is not None or pw is not None:
            creds.append(WifiCredential(role, ssid, pw))
    return creds
