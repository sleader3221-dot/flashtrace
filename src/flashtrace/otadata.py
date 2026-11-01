"""otadata (OTA select entries) parser.

Confirmed against ESP-IDF v5.3.1:

* ``esp_flash_partitions.h``: ``esp_ota_select_entry_t { u32 ota_seq;
  u8 seq_label[20]; u32 ota_state; u32 crc; }`` (32 bytes), two copies, one at
  the start of each 4 KB sector of the otadata partition.
* ``bootloader_common_loader.c``: ``crc = esp_rom_crc32_le(UINT32_MAX, &ota_seq, 4)``;
  ``otatool.py`` computes the same value as ``binascii.crc32(seq_le, 0xFFFFFFFF)``.
  An entry is *valid* (selectable by the bootloader) iff ``ota_seq != 0xFFFFFFFF``,
  ``ota_state`` is not INVALID/ABORTED, and the CRC matches.
* The bootloader boots the valid entry with the highest ``ota_seq``; the slot is
  ``(ota_seq - 1) % number_of_ota_app_partitions``.
"""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass, field

from flashtrace.model import Anomaly, ByteSource

ENTRY_LEN = 32
SECTOR = 0x1000
SEQ_UNSET = 0xFFFFFFFF

OTA_STATES: dict[int, str] = {
    0x0: "NEW",
    0x1: "PENDING_VERIFY",
    0x2: "VALID",
    0x3: "INVALID",
    0x4: "ABORTED",
    0xFFFFFFFF: "UNDEFINED",
}
STATE_INVALID = 0x3
STATE_ABORTED = 0x4


def ota_seq_crc(seq: int) -> int:
    return binascii.crc32(struct.pack("<I", seq & 0xFFFFFFFF), 0xFFFFFFFF) & 0xFFFFFFFF


@dataclass(frozen=True)
class OtaSelectEntry:
    index: int  # 0 or 1 (sector)
    offset: int  # absolute
    seq: int
    seq_label: bytes
    state: int
    crc: int

    @property
    def erased(self) -> bool:
        return self.seq == SEQ_UNSET and self.crc == 0xFFFFFFFF

    @property
    def crc_ok(self) -> bool:
        return self.crc == ota_seq_crc(self.seq)

    @property
    def state_name(self) -> str:
        return OTA_STATES.get(self.state, f"UNKNOWN({self.state:#x})")

    @property
    def valid(self) -> bool:
        """Selectable by the bootloader (mirrors ``bootloader_common_ota_select_valid``)."""
        return (
            self.seq != SEQ_UNSET
            and self.state not in (STATE_INVALID, STATE_ABORTED)
            and self.crc_ok
        )


@dataclass(frozen=True)
class OtaData:
    offset: int  # absolute
    entries: tuple[OtaSelectEntry, ...]
    num_ota_apps: int
    active_entry: int | None  # index into entries of the selected entry
    active_slot: int | None  # ota_N slot number, None => factory / no OTA
    anomalies: tuple[Anomaly, ...] = field(default_factory=tuple)

    @property
    def active(self) -> OtaSelectEntry | None:
        return None if self.active_entry is None else self.entries[self.active_entry]


def parse_otadata(data: ByteSource, base_offset: int = 0, num_ota_apps: int = 0) -> OtaData:
    """Parse both otadata sectors. ``num_ota_apps`` = number of ota_N app partitions."""
    mv = memoryview(data)
    anomalies: list[Anomaly] = []
    entries: list[OtaSelectEntry] = []
    if len(mv) < 2 * SECTOR:
        anomalies.append(
            Anomaly(
                "OTA_SHORT_PARTITION",
                f"otadata is {len(mv)} bytes; expected at least {2 * SECTOR}",
                base_offset,
                len(mv),
                {"size": len(mv)},
            )
        )
    for i in range(2):
        pos = i * SECTOR
        if pos + ENTRY_LEN > len(mv):
            break
        seq, label, state, crc = struct.unpack_from("<I20sII", mv, pos)
        entry = OtaSelectEntry(i, base_offset + pos, seq, bytes(label), state, crc)
        entries.append(entry)
        if not entry.erased and entry.seq != SEQ_UNSET and not entry.crc_ok:
            anomalies.append(
                Anomaly(
                    "OTA_CRC_BAD",
                    f"otadata entry {i} CRC {crc:#010x} != expected {ota_seq_crc(seq):#010x}",
                    base_offset + pos,
                    ENTRY_LEN,
                    {"entry": i, "seq": seq, "stored": crc, "computed": ota_seq_crc(seq)},
                )
            )
        if state not in OTA_STATES:
            anomalies.append(
                Anomaly(
                    "OTA_UNKNOWN_STATE",
                    f"otadata entry {i} has unknown ota_state {state:#x}",
                    base_offset + pos + 24,
                    4,
                    {"entry": i, "state": state},
                )
            )

    valid = [e for e in entries if e.valid]
    active_entry: int | None = None
    active_slot: int | None = None
    if valid:
        best = max(valid, key=lambda e: e.seq)
        active_entry = best.index
        if num_ota_apps > 0 and best.seq > 0:
            active_slot = (best.seq - 1) % num_ota_apps
        elif num_ota_apps <= 0:
            anomalies.append(
                Anomaly(
                    "OTA_NO_OTA_APPS",
                    "otadata selects an OTA slot but no ota_N app partitions exist",
                    best.offset,
                    ENTRY_LEN,
                    {"seq": best.seq},
                )
            )
    return OtaData(
        offset=base_offset,
        entries=tuple(entries),
        num_ota_apps=num_ota_apps,
        active_entry=active_entry,
        active_slot=active_slot,
        anomalies=tuple(anomalies),
    )
