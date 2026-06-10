from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser
from utils.utmp import parse_utmp_records


class WtmpParser(BaseParser):
    """wtmp/btmp-Parser auf Basis des korrekten 384-Byte-Records (utils/utmp).

    Review-Fix CRITICAL #4: der fruehere eigene Struct ('<hh32s4s4shhiii4i20s',
    96 Bytes) lag 4x daneben — User/Host/Timestamps waren Garbage.
    """
    name          = 'wtmp'
    file_patterns = ['wtmp', 'wtmp.*']
    binary        = True

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('wtmp') and not path.name.endswith('.db')

    MAX_BYTES = 50 * 1024 * 1024   # wtmp ist realistisch < wenige MB

    def parse(self, path: Path) -> List[ForensicEvent]:
        try:
            with path.open('rb') as f:
                data = f.read(self.MAX_BYTES)
        except (PermissionError, OSError):
            return []
        events = []
        for rec in parse_utmp_records(data):
            if rec['ts_sec'] <= 0:
                continue
            tname = rec['type_name']
            if tname not in ('user_process', 'dead_process', 'boot_time'):
                continue
            ts  = datetime.fromtimestamp(rec['ts_sec'], tz=timezone.utc)
            sev = 'medium' if tname == 'user_process' else 'info'
            events.append(self.make_event(
                ts, 'wtmp', tname,
                f"{tname}: User={rec['user']} Host={rec['host']} Line={rec['line']}",
                user=rec['user'] or None,
                ip=rec['host'] if rec['host'] and rec['host'][0].isdigit() else None,
                severity=sev,
            ))
        return events
