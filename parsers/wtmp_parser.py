import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

UTMP_STRUCT = '<hh32s4s4shhiii4i20s'
UTMP_SIZE   = struct.calcsize(UTMP_STRUCT)

UT_TYPES = {
    0: 'empty', 1: 'run_level', 2: 'boot_time',
    3: 'new_time', 4: 'old_time', 5: 'init_process',
    6: 'login_process', 7: 'user_process', 8: 'dead_process',
}


class WtmpParser(BaseParser):
    name          = 'wtmp'
    file_patterns = ['wtmp', 'wtmp.*']
    binary        = True

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('wtmp')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        try:
            data = path.read_bytes()
        except PermissionError:
            return []
        offset = 0
        while offset + UTMP_SIZE <= len(data):
            chunk = data[offset:offset + UTMP_SIZE]
            offset += UTMP_SIZE
            try:
                fields = struct.unpack(UTMP_STRUCT, chunk)
            except struct.error:
                continue
            ut_type = fields[0]
            ut_user = fields[4].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_host = fields[3].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_tv_sec = fields[9]
            if ut_tv_sec == 0:
                continue
            ts        = datetime.fromtimestamp(ut_tv_sec, tz=timezone.utc)
            type_name = UT_TYPES.get(ut_type, 'unknown')
            if type_name in ('user_process', 'dead_process', 'boot_time'):
                sev = 'medium' if type_name == 'user_process' else 'info'
                events.append(self.make_event(
                    ts, 'wtmp', type_name,
                    f'{type_name}: User={ut_user} Host={ut_host}',
                    user=ut_user, severity=sev
                ))
        return events
