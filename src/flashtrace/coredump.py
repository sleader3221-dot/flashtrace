"""Coredump partition summary.

From ESP-IDF v5.3.1 ``espcoredump/include_core_dump/esp_core_dump_types.h``:
``core_dump_header_t { u32 data_len; u32 version; u32 tasks_num; u32 tcb_sz;
u32 mem_segs_num; u32 chip_rev; }`` with ``version = chip_id << 16 | major << 8 |
minor`` where major 0 = binary format, 1 = ELF (0x0102 CRC32, 0x0103 SHA256).
ELF dumps contain an ELF32 core file (``\\x7fELF``, e_type ET_CORE). An erased
partition reads 0xFF (``BLANK_COREDUMP_SIZE`` = 0xFFFFFFFF).

The task count is only reported for the binary format, where it is a header field;
it is sanity-bounded and dropped (with an anomaly) when implausible.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Literal

from flashtrace.io import is_blank
from flashtrace.model import Anomaly, ByteSource

MAX_TASKS = 256
ELF_MAGIC = b"\x7fELF"

CoreFormat = Literal["empty", "elf", "binary", "unknown"]


@dataclass(frozen=True)
class CoreDump:
    partition: str | None
    offset: int
    size: int
    format: CoreFormat
    data_len: int | None
    version: int | None
    chip_id: int | None
    tasks_num: int | None
    elf_offset: int | None  # absolute offset of the ELF header, if found
    anomalies: tuple[Anomaly, ...] = field(default_factory=tuple)

    @property
    def present(self) -> bool:
        return self.format != "empty"


def parse_coredump(
    data: ByteSource, base_offset: int = 0, partition: str | None = None
) -> CoreDump:
    mv = memoryview(data)
    if is_blank(mv):
        return CoreDump(partition, base_offset, len(mv), "empty", None, None, None, None, None)
    anomalies: list[Anomaly] = []
    data_len = version = chip = tasks = None
    if len(mv) >= 24:
        data_len, version, tasks_raw = struct.unpack_from("<III", mv, 0)
        chip = version >> 16
        major = (version >> 8) & 0xFF
        if data_len > len(mv):
            anomalies.append(
                Anomaly(
                    "CORE_BAD_LENGTH",
                    f"coredump data_len {data_len} exceeds partition size {len(mv)}",
                    base_offset,
                    4,
                    {"data_len": data_len},
                )
            )
    else:
        major = -1
        tasks_raw = 0
    head = bytes(mv[:64])
    elf_rel = head.find(ELF_MAGIC)
    if elf_rel >= 0:
        fmt: CoreFormat = "elf"
    elif major == 0 and version is not None:
        fmt = "binary"
        if 0 < tasks_raw <= MAX_TASKS:
            tasks = tasks_raw
        else:
            anomalies.append(
                Anomaly(
                    "CORE_BAD_TASK_COUNT",
                    f"implausible coredump task count {tasks_raw}",
                    base_offset + 8,
                    4,
                    {"tasks_num": tasks_raw},
                )
            )
    else:
        fmt = "unknown"
    return CoreDump(
        partition,
        base_offset,
        len(mv),
        fmt,
        data_len,
        version,
        chip,
        tasks,
        base_offset + elf_rel if elf_rel >= 0 else None,
        tuple(anomalies),
    )
