import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import duckdb

from models.event import ForensicEvent

_DDL = """
CREATE SEQUENCE IF NOT EXISTS events_id_seq START 1;
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER DEFAULT nextval('events_id_seq') PRIMARY KEY,
    timestamp     TIMESTAMP NOT NULL,
    source        VARCHAR   DEFAULT '',
    event_type    VARCHAR   DEFAULT '',
    message       VARCHAR   DEFAULT '',
    username      VARCHAR,
    ip            VARCHAR,
    process       VARCHAR,
    file_path     VARCHAR,
    severity      VARCHAR   DEFAULT 'info',
    anomaly_score DOUBLE    DEFAULT 0.0,
    mitre_tags    VARCHAR   DEFAULT '[]',
    evidence      VARCHAR   DEFAULT '',
    orig_path     VARCHAR   DEFAULT '',
    source_file   VARCHAR   DEFAULT '',
    partition_label VARCHAR DEFAULT '',
    parser_name   VARCHAR   DEFAULT '',
    extraction    VARCHAR   DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ts  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_sev ON events(severity);
"""


class EventStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[duckdb.DuckDBPyConnection] = None

    def open(self) -> 'EventStore':
        self._conn = duckdb.connect(str(self.db_path))
        for stmt in _DDL.strip().split(';'):
            stmt = stmt.strip()
            if stmt:
                self._conn.execute(stmt)
        return self

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()

    # ── Schreiben ─────────────────────────────────────────────────────────────

    def insert_events(self, events: List[ForensicEvent]):
        rows = [
            (e.timestamp, e.source, e.event_type, e.message,
             e.user, e.ip, e.process, e.file_path, e.severity,
             e.anomaly_score, json.dumps(e.mitre_tags),
             e.evidence, e.orig_path, e.source_file, e.partition,
             e.parser_name, e.extraction)
            for e in events
        ]
        self._conn.executemany(
            "INSERT INTO events(timestamp,source,event_type,message,username,"
            "ip,process,file_path,severity,anomaly_score,mitre_tags,"
            "evidence,orig_path,source_file,partition_label,parser_name,extraction) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    # ── Lesen ──────────────────────────────────────────────────────────────────

    def iter_events(self, batch: int = 1000) -> Iterator[ForensicEvent]:
        """Streamt ForensicEvent-Objekte aus der DB — Stages 07-10 merken keinen Unterschied."""
        cur = self._conn.execute(
            "SELECT id,timestamp,source,event_type,message,username,"
            "ip,process,file_path,severity,anomaly_score,mitre_tags,"
            "evidence,orig_path,source_file,partition_label,parser_name,extraction "
            "FROM events ORDER BY timestamp"
        )
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for row in rows:
                yield self._row_to_event(row)

    def get_all_sorted(self) -> List[ForensicEvent]:
        """Lädt alle Events als sortierte ForensicEvent-Liste (für ctx.normalized_events)."""
        rows = self._conn.execute(
            "SELECT id,timestamp,source,event_type,message,username,"
            "ip,process,file_path,severity,anomaly_score,mitre_tags,"
            "evidence,orig_path,source_file,partition_label,parser_name,extraction "
            "FROM events ORDER BY timestamp"
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def count_by_source(self) -> Dict[str, int]:
        rows = self._conn.execute(
            "SELECT source, COUNT(*) FROM events GROUP BY source"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    # ── Feld-Bereinigung (Stage 08) ────────────────────────────────────────────

    def cleanup_required_fields(self):
        """Bereinigt Pflichtfelder. Timestamps werden NICHT mehr angefasst —
        die Konversion nach UTC passiert genau EINMAL in den Parsern mit der
        Image-Zeitzone (Review-Fix CRITICAL #6: das fruehere zweite
        Lokalisieren verschob bereits korrekte UTC-Quellen wie mactime,
        wtmp, journald und audit um den Zeitzonen-Offset)."""
        self._conn.execute("""
            UPDATE events SET
                source     = CASE WHEN source     = '' OR source     IS NULL
                                  THEN 'unknown' ELSE source     END,
                event_type = CASE WHEN event_type = '' OR event_type IS NULL
                                  THEN 'generic' ELSE event_type END,
                severity   = CASE WHEN severity   = '' OR severity   IS NULL
                                  THEN 'info'    ELSE severity   END
        """)

    # ── Hilfsmethode ──────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_event(row) -> ForensicEvent:
        ts = row[1]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return ForensicEvent(
            timestamp     = ts,
            source        = row[2] or '',
            event_type    = row[3] or '',
            message       = row[4] or '',
            user          = row[5],
            ip            = row[6],
            process       = row[7],
            file_path     = row[8],
            severity      = row[9] or 'info',
            anomaly_score = float(row[10] or 0.0),
            mitre_tags    = json.loads(row[11] or '[]'),
            evidence      = (row[12] or '') if len(row) > 12 else '',
            orig_path     = (row[13] or '') if len(row) > 13 else '',
            source_file   = (row[14] or '') if len(row) > 14 else '',
            partition     = (row[15] or '') if len(row) > 15 else '',
            parser_name   = (row[16] or '') if len(row) > 16 else '',
            extraction    = (row[17] or '') if len(row) > 17 else '',
        )
