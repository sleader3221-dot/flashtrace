"""Build a decrypted *view* of a dump from user-supplied keys.

Which regions flash encryption covers comes from ESP-IDF v5.3.1
``docs/en/security/flash-encryption.rst`` ("Encrypted Partitions"): the
second-stage bootloader, the partition table, the NVS key partition, otadata, all
``app`` partitions, and any partition with the ``encrypted`` flag. NVS partitions are
never flash-encrypted; they use NVS encryption with the key stored in nvs_keys.

The scheme (ESP32 tweaked-AES vs AES-XTS) is not recorded in the dump, so both are
tried and the one that reveals a partition table at the expected offset wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from flashtrace.crypto import Scheme, decrypt_nvs, flash_crypt, load_flash_key, parse_nvs_keys
from flashtrace.model import sha256_hex
from flashtrace.nvs import parse_nvs
from flashtrace.partition import (
    DEFAULT_TABLE_OFFSET,
    MAX_TABLE_LENGTH,
    TYPE_APP,
    TYPE_DATA,
    PartitionTable,
    parse_partition_table,
    plausible_table,
)

SUBTYPE_OTA, SUBTYPE_NVS, SUBTYPE_NVS_KEYS = 0x00, 0x02, 0x04


@dataclass(frozen=True)
class KeyMaterial:
    flash_key: bytes | None = None  # raw key file bytes (16/24/32/64)
    flash_crypt_conf: int = 0xF  # ESP32 FLASH_CRYPT_CONFIG eFuse value
    nvs_key: bytes | None = None  # 64 bytes, or a whole nvs_keys partition image


@dataclass
class DecryptionInfo:
    original_sha256: str
    flash_scheme: Scheme | None = None
    flash_regions: list[tuple[str, int, int]] = field(default_factory=list)  # (what, off, len)
    nvs_partitions: list[str] = field(default_factory=list)
    nvs_key_source: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def flash_decrypted(self) -> bool:
        return self.flash_scheme is not None


def _align(off: int, length: int, size: int) -> tuple[int, int]:
    start = max(0, min(off, size)) & ~0xF
    end = min(off + length, size) & ~0xF
    return start, max(0, end - start)


def _try_scheme(dump: bytes, key: bytes, scheme: Scheme, conf: int, table_off: int) -> bool:
    start, n = _align(table_off, MAX_TABLE_LENGTH, len(dump))
    if n < 32:
        return False
    plain = flash_crypt(dump[start : start + n], start, key, scheme, flash_crypt_conf=conf)
    probe = bytearray(len(dump[: start + n]))
    probe[start : start + n] = plain
    return plausible_table(bytes(probe), table_off)


def _table(view: bytearray, off: int) -> PartitionTable:
    return parse_partition_table(bytes(view[off : off + MAX_TABLE_LENGTH]), off)


def decrypt_view(
    dump: bytes, keys: KeyMaterial, table_offset: int = DEFAULT_TABLE_OFFSET
) -> tuple[bytes, DecryptionInfo]:
    info = DecryptionInfo(original_sha256=sha256_hex(dump))
    view = bytearray(dump)
    if keys.flash_key is not None:
        _flash_pass(dump, view, keys, info, table_offset)
    if keys.nvs_key is not None or info.flash_decrypted:
        _nvs_pass(view, keys, info, table_offset)
    return bytes(view), info


def _flash_pass(
    dump: bytes, view: bytearray, keys: KeyMaterial, info: DecryptionInfo, table_offset: int
) -> None:
    if keys.flash_key is None:
        return
    schemes: tuple[Scheme, ...] = ("aes-xts", "esp32")
    found: tuple[Scheme, bytes] | None = None
    for scheme in schemes:
        try:
            k = load_flash_key(keys.flash_key, scheme)
        except ValueError:
            continue
        if _try_scheme(dump, k, scheme, keys.flash_crypt_conf, table_offset):
            found = (scheme, k)
            break
    if found is None:
        info.errors.append("flash key did not reveal a partition table with either scheme")
        return
    scheme_s, key = found
    info.flash_scheme = scheme_s

    def dec(what: str, off: int, length: int) -> None:
        start, n = _align(off, length, len(dump))
        if n <= 0:
            return
        view[start : start + n] = flash_crypt(
            dump[start : start + n], start, key, scheme_s, flash_crypt_conf=keys.flash_crypt_conf
        )
        info.flash_regions.append((what, start, n))

    # bootloader region: ESP32/S2 at 0x1000, newer chips at 0x0 (P4/C5 at 0x2000)
    boot_start = 0x1000 if scheme_s == "esp32" else 0x0
    dec("bootloader", boot_start, table_offset - boot_start)
    dec("partition_table", table_offset, MAX_TABLE_LENGTH)
    table = parse_partition_table(
        bytes(view[table_offset : table_offset + MAX_TABLE_LENGTH]), table_offset
    )
    for e in table.entries:
        enc = (
            e.type == TYPE_APP
            or (e.type == TYPE_DATA and e.subtype in (SUBTYPE_OTA, SUBTYPE_NVS_KEYS))
            or e.encrypted
        )
        if enc and not (e.type == TYPE_DATA and e.subtype == SUBTYPE_NVS):
            dec(e.label, e.offset, e.size)


def _nvs_pass(view: bytearray, keys: KeyMaterial, info: DecryptionInfo, table_offset: int) -> None:
    table = parse_partition_table(
        bytes(view[table_offset : table_offset + MAX_TABLE_LENGTH]), table_offset
    )
    nvs_key: bytes | None = None
    if keys.nvs_key is not None:
        nvs_key = keys.nvs_key if len(keys.nvs_key) == 64 else parse_nvs_keys(keys.nvs_key)
        info.nvs_key_source = "supplied"
        if nvs_key is None:
            info.errors.append("supplied NVS key is neither 64 bytes nor a valid nvs_keys image")
            return
    else:
        for e in table.find(TYPE_DATA, SUBTYPE_NVS_KEYS):
            nvs_key = parse_nvs_keys(view[e.offset : e.offset + e.size])
            if nvs_key is not None:
                info.nvs_key_source = f"partition {e.label}"
                break
    if nvs_key is None:
        return
    for e in table.find(TYPE_DATA, SUBTYPE_NVS):
        start, end = e.offset, min(e.offset + e.size, len(view))
        if end <= start:
            continue
        part = bytes(view[start:end])
        if not parse_nvs(part, start, e.label, nvs_keys_present=True).encrypted:
            continue  # already plaintext
        plain = decrypt_nvs(part, nvs_key)
        if parse_nvs(plain, start, e.label, nvs_keys_present=True).encrypted:
            info.errors.append(f"NVS key did not decrypt partition {e.label}")
            continue
        view[start:end] = plain
        info.nvs_partitions.append(e.label)
