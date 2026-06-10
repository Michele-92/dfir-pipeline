import subprocess
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

LEVEL_MAP = {0: 'critical', 1: 'critical', 2: 'critical',
             3: 'high', 4: 'medium', 5: 'medium', 6: 'info', 7: 'info'}


class JournaldParser(BaseParser):
    """systemd-Journal via journalctl --file.

    Review-Nachfix (Stage-6-Haenger): journalctl-Output wird GESTREAMT
    statt komplett gepuffert — ein einziges Journal kann als JSON mehrere
    GB erzeugen und hat vorher den Worker (OOM) und anschliessend den
    sequenziellen Rettungspfad (Swap-Freeze) gerissen.
    Harte Limits: MAX_EVENTS Events und TIMEOUT_S Sekunden pro Datei.
    """
    name          = 'journald'
    file_patterns = ['*.journal']
    binary        = True

    MAX_EVENTS = 200_000
    TIMEOUT_S  = 300

    def can_parse(self, path: Path) -> bool:
        return path.suffix == '.journal'

    def parse(self, path: Path) -> List[ForensicEvent]:
        events: List[ForensicEvent] = []
        try:
            proc = subprocess.Popen(
                ['journalctl', '--file', str(path),
                 '--output=json', '--no-pager'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, errors='replace',
            )
        except FileNotFoundError:
            return events

        deadline  = time.monotonic() + self.TIMEOUT_S
        truncated = False
        try:
            for line in proc.stdout:
                if len(events) >= self.MAX_EVENTS or time.monotonic() > deadline:
                    truncated = True
                    break
                try:
                    entry = json.loads(line)
                    ts_us = int(entry.get('__REALTIME_TIMESTAMP', 0))
                    if not ts_us:
                        continue
                    ts   = datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc)
                    msg  = str(entry.get('MESSAGE', ''))[:500]
                    unit = entry.get('_SYSTEMD_UNIT', '')
                    prio = int(entry.get('PRIORITY', 6))
                    events.append(self.make_event(
                        ts, 'journald', 'system', msg,
                        process=unit,
                        severity=LEVEL_MAP.get(prio, 'info'),
                    ))
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
        finally:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass

        if truncated and events:
            events.append(self.make_event(
                events[-1].timestamp, 'journald', 'journal_truncated',
                f'Journal {path.name}: Limit erreicht '
                f'({self.MAX_EVENTS:,} Events / {self.TIMEOUT_S}s) — '
                f'Datei nur teilweise verarbeitet',
                severity='medium',
            ))
        return events
