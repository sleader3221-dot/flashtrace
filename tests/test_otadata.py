import binascii
import struct

import pytest

from flashtrace.otadata import ota_seq_crc, parse_otadata
from tests.fixtures.generator import otadata, otadata_entry

BASE = 0xD000


def test_crc_matches_otatool_formula() -> None:
    for seq in (0, 1, 2, 7, 0x12345678, 0xFFFFFFFE):
        expected = binascii.crc32(struct.pack("I", seq), 0xFFFFFFFF) % (1 << 32)
        assert ota_seq_crc(seq) == expected


def test_blank_otadata_boots_factory() -> None:
    o = parse_otadata(otadata((None, None)), BASE, 2)
    assert o.active is None and o.active_slot is None and o.anomalies == ()
    assert all(e.erased and not e.valid for e in o.entries)


@pytest.mark.parametrize(
    ("seqs", "n_apps", "slot", "entry"),
    [
        ((1, None), 2, 0, 0),
        ((1, 2), 2, 1, 1),
        ((3, 2), 2, 0, 0),
        ((5, 4), 3, 1, 0),
        ((None, 16), 16, 15, 1),
    ],
)
def test_active_slot(
    seqs: tuple[int | None, int | None], n_apps: int, slot: int, entry: int
) -> None:
    a, b = (None if s is None else otadata_entry(s, 2) for s in seqs)
    data = otadata((a, b))
    o = parse_otadata(data, BASE, n_apps)
    assert (o.active_slot, o.active_entry) == (slot, entry)
    assert o.entries[1].offset == BASE + 0x1000
    assert o.anomalies == ()


def test_bad_crc_entry_is_ignored() -> None:
    o = parse_otadata(otadata((otadata_entry(1, 2), otadata_entry(2, 2, bad_crc=True))), BASE, 2)
    assert o.active_slot == 0 and not o.entries[1].crc_ok
    assert [a.kind for a in o.anomalies] == ["OTA_CRC_BAD"]
    assert o.anomalies[0].offset == BASE + 0x1000


@pytest.mark.parametrize("state", [3, 4])
def test_invalid_or_aborted_not_selected(state: int) -> None:
    o = parse_otadata(otadata((otadata_entry(1, 2), otadata_entry(2, state))), BASE, 2)
    assert o.active_slot == 0
    assert o.entries[1].crc_ok and not o.entries[1].valid


def test_pending_verify_is_selected() -> None:
    o = parse_otadata(otadata((otadata_entry(1, 2), otadata_entry(2, 1))), BASE, 2)
    active = o.active
    assert active is not None and active.state_name == "PENDING_VERIFY" and o.active_slot == 1


def test_unknown_state_and_short_partition() -> None:
    o = parse_otadata(otadata((otadata_entry(1, 0x77), None)), BASE, 2)
    assert [a.kind for a in o.anomalies] == ["OTA_UNKNOWN_STATE"]
    assert o.entries[0].state_name.startswith("UNKNOWN")
    o = parse_otadata(otadata_entry(1, 2), BASE, 2)
    assert [a.kind for a in o.anomalies] == ["OTA_SHORT_PARTITION"] and len(o.entries) == 1
    o = parse_otadata(b"", BASE, 2)
    assert o.entries == () and o.active is None


def test_ota_selected_without_ota_apps() -> None:
    o = parse_otadata(otadata((otadata_entry(1, 2), None)), BASE, 0)
    assert o.active_slot is None and [a.kind for a in o.anomalies] == ["OTA_NO_OTA_APPS"]
