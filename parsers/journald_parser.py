import subprocess
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser


class JournaldParser(BaseParser):
    name          = 'journald'
    file_patterns = ['*.journal']
    binary        = True

    def can_parse(self, path: Path) -> bool:
        return path.suffix == '.journal'

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {0:'critical',1:'critical',2:'critical',
                     3:'high',4:'medium',5:'medium',6:'info',7:'info'}
        try:
            result = subprocess.run(
                ['journalctl', '--file', str(path), '--output=json', '--no-pager'],
                capture_output=True, text=True, timeout=120
            )
            for line in result.stdout.splitlines():
                try:
                    entry = json.loads(line)
                    ts_us = int(entry.get('__REALTIME_TIMESTAMP', 0))
                    ts    = datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc)
                    msg   = str(entry.get('MESSAGE', ''))
                    unit  = entry.get('_SYSTEMD_UNIT', '')
                    prio  = int(entry.get('PRIORITY', 6))
                    events.append(self.make_event(
                        timestamp  = ts,
                        source     = 'journald',
                        event_type = 'system',
                        message    = msg,
                        process    = unit,
                        severity   = LEVEL_MAP.get(prio, 'info'),
                        raw        = entry,
                    ))
                except (json.JSONDecodeError, ValueError):
                    continue
        except FileNotFoundError:
            pass
        return events
