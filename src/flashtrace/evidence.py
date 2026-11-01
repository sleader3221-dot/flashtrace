"""SQLite evidence store.

Tables (CLAUDE.md "Core data model"):
``dump``, ``artifact``, ``finding``, ``evidence``, ``timeline``.
Timeline rows record *where* a timestamp came from; they are device-reported
values, never trusted wall-clock.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from flashtrace.model import Evidence, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS dump (
    sha256      TEXT PRIMARY KEY,
    size        INTEGER NOT NULL,
    chip        TEXT,
    analysed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifact (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_sha256 TEXT NOT NULL REFERENCES dump(sha256),
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    partition   TEXT,
    offset      INTEGER NOT NULL,
    length      INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    meta        TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS finding (
    id          TEXT NOT NULL,
    dump_sha256 TEXT NOT NULL REFERENCES dump(sha256),
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL,
    attck       TEXT NOT NULL,
    confidence  REAL NOT NULL,
    PRIMARY KEY (dump_sha256, id)
);
CREATE TABLE IF NOT EXISTS evidence (
    dump_sha256 TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    partition   TEXT,
    offset      INTEGER NOT NULL,
    length      INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    PRIMARY KEY (dump_sha256, finding_id, seq),
    FOREIGN KEY (dump_sha256, finding_id) REFERENCES finding(dump_sha256, id)
);
CREATE TABLE IF NOT EXISTS timeline (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_sha256 TEXT NOT NULL REFERENCES dump(sha256),
    ts_source   TEXT NOT NULL,
    value       TEXT NOT NULL,
    finding_id  TEXT
);
"""


class EvidenceStore:
    """Thin, explicit wrapper around a SQLite database (``:memory:`` allowed)."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._conn.commit()
        self._conn.close()

    def add_dump(
        self, sha256: str, size: int, chip: str | None, analysed_at: datetime | None = None
    ) -> None:
        ts = (analysed_at or datetime.now(UTC)).isoformat()
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO dump(sha256, size, chip, analysed_at) VALUES (?,?,?,?)",
                (sha256, size, chip, ts),
            )

    def add_artifact(
        self,
        dump_sha256: str,
        kind: str,
        name: str,
        evidence: Evidence,
        meta: Mapping[str, Any] | None = None,
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO artifact(dump_sha256, kind, name, partition, offset, length, sha256,"
                " meta) VALUES (?,?,?,?,?,?,?,?)",
                (
                    dump_sha256,
                    kind,
                    name,
                    evidence.partition,
                    evidence.offset,
                    evidence.length,
                    evidence.sha256,
                    json.dumps(dict(meta or {}), sort_keys=True, default=str),
                ),
            )
        return int(cur.lastrowid or 0)

    def add_finding(self, dump_sha256: str, finding: Finding) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO finding(id, dump_sha256, rule_id, severity, title, detail,"
                " attck, confidence) VALUES (?,?,?,?,?,?,?,?)",
                (
                    finding.id,
                    dump_sha256,
                    finding.rule_id,
                    finding.severity,
                    finding.title,
                    json.dumps(dict(finding.detail), sort_keys=True, default=str),
                    json.dumps(list(finding.attck)),
                    finding.confidence,
                ),
            )
            self._conn.execute(
                "DELETE FROM evidence WHERE dump_sha256 = ? AND finding_id = ?",
                (dump_sha256, finding.id),
            )
            self._conn.executemany(
                "INSERT INTO evidence(dump_sha256, finding_id, seq, partition, offset, length,"
                " sha256) VALUES (?,?,?,?,?,?,?)",
                [
                    (dump_sha256, finding.id, i, e.partition, e.offset, e.length, e.sha256)
                    for i, e in enumerate(finding.evidence)
                ],
            )

    def add_timeline(
        self, dump_sha256: str, ts_source: str, value: str, finding_id: str | None = None
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO timeline(dump_sha256, ts_source, value, finding_id) VALUES (?,?,?,?)",
                (dump_sha256, ts_source, value, finding_id),
            )

    def findings(self, dump_sha256: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT id, rule_id, severity, title, detail, attck, confidence FROM finding"
            " WHERE dump_sha256 = ? ORDER BY rule_id, id",
            (dump_sha256,),
        ).fetchall()
        out: list[Finding] = []
        for fid, rule_id, severity, title, detail, attck, confidence in rows:
            ev_rows = self._conn.execute(
                "SELECT partition, offset, length, sha256 FROM evidence"
                " WHERE dump_sha256 = ? AND finding_id = ? ORDER BY seq",
                (dump_sha256, fid),
            ).fetchall()
            out.append(
                Finding(
                    id=fid,
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    detail=json.loads(detail),
                    evidence=tuple(Evidence(p, o, n, s) for p, o, n, s in ev_rows),
                    attck=tuple(json.loads(attck)),
                    confidence=float(confidence),
                )
            )
        return out

    def timeline(self, dump_sha256: str) -> list[tuple[str, str, str | None]]:
        rows = self._conn.execute(
            "SELECT ts_source, value, finding_id FROM timeline WHERE dump_sha256 = ? ORDER BY id",
            (dump_sha256,),
        ).fetchall()
        return [(str(a), str(b), None if c is None else str(c)) for a, b, c in rows]

    def artifacts(self, dump_sha256: str) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT kind, name, partition, offset, length, sha256, meta FROM artifact"
            " WHERE dump_sha256 = ? ORDER BY id",
            (dump_sha256,),
        )
        return [
            {
                "kind": k,
                "name": n,
                "partition": p,
                "offset": o,
                "length": ln,
                "sha256": s,
                "meta": json.loads(m),
            }
            for k, n, p, o, ln, s, m in cur.fetchall()
        ]
