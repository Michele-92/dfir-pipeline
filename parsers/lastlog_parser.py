import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

LASTLOG_STRUCT = '<l32s256s'
LASTLOG_SIZE   = struct.calcsize(LASTLOG_STRUCT)


class LastlogParser(BaseParser):
    name          = 'lastlog'
    file_patterns = ['lastlog']
    binary        = True

    def can_parse(self, path: Path) -> bool:
        return path.name == 'lastlog'

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        data   = path.read_bytes()
        uid    = 0
        offset = 0
        while offset + LASTLOG_SIZE <= len(data):
            chunk = data[offset:offset + LASTLOG_SIZE]
            offset += LASTLOG_SIZE
            ts_sec, line, host = struct.unpack(LASTLOG_STRUCT, chunk)
            if ts_sec > 0:
                ts   = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                host = host.rstrip(b'\x00').decode('utf-8', errors='replace')
                events.append(self.make_event(
                    ts, 'lastlog', 'last_login',
                    f'Letzter Login UID={uid} von {host}',
                    severity='info'
                ))
            uid += 1
        return events
