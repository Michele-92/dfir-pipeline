import re
from pathlib import Path
from typing import List
from datetime import datetime, timezone

from .base_parser import BaseParser
from models.event import ForensicEvent


class MACTimeParser(BaseParser):
    name          = 'mactime'
    file_patterns = ['mactime_timeline']

    # mactime CSV-Format: date,size,type,mode,uid,gid,inode,filename
    # Beispiel: Mon Nov 28 2022 14:22:40,12345,...a..,r/rrwxrwxrwx,0,0,12345,/etc/passwd
    _RE = re.compile(
        r'^(?P<date>\w{3} \w{3}\s+\d+ \d{4} \d{2}:\d{2}:\d{2}),'
        r'(?P<size>\d+),'
        r'(?P<macb>[macb\.]+),'
        r'(?P<mode>[^\,]+),'
        r'(?P<uid>\d+),'
        r'(?P<gid>\d+),'
        r'(?P<inode>[^\,]+),'
        r'(?P<filename>.+)$'
    )

    _MACB_MAP = {
        'm': 'modified',
        'a': 'accessed',
        'c': 'changed',
        'b': 'born',
    }

    def can_parse(self, file_path: Path) -> bool:
        return 'mactime_timeline' in file_path.name.lower()

    def parse(self, file_path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(file_path):
            if not line or line.startswith('#'):
                continue
            m = self._RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(
                    m.group('date').strip(), '%a %b %d %Y %H:%M:%S'
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            macb     = m.group('macb')
            filename = m.group('filename').strip()
            size     = m.group('size')

            active = [self._MACB_MAP[c] for c in macb if c in self._MACB_MAP]
            label  = '+'.join(active) if active else 'accessed'

            severity = 'info'
            if any(s in filename for s in ['/tmp/', '/var/tmp/', '/dev/shm']):
                severity = 'medium'
            if filename.startswith('* '):
                severity = 'high'
                filename = filename[2:]

            events.append(self.make_event(
                timestamp  = ts,
                source     = 'mactime',
                event_type = f'filesystem_{label}',
                message    = f'[{macb}] {filename} ({size} bytes)',
                file_path  = filename,
                severity   = severity,
            ))
        return events
