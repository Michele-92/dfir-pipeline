import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

SAMBA_TS = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\]')
SAMBA_IP = re.compile(r'(?:from|IP)\s+([\d.]+)')


class SambaParser(BaseParser):
    name          = 'samba'
    file_patterns = ['samba/log.*', 'log.smbd', 'log.nmbd']

    def can_parse(self, path: Path) -> bool:
        return 'samba' in str(path).lower() or path.name.startswith('log.s')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        last_ts = ''   # Samba schreibt '[Timestamp]' und Message auf getrennte Zeilen
        for line in self.read_lines(path):
            mt = SAMBA_TS.search(line)
            if mt:
                last_ts = mt.group(1)
            ts = mt.group(1) if mt else last_ts
            mi = SAMBA_IP.search(line)
            ip = mi.group(1) if mi else None
            sev = 'high' if any(w in line.lower() for w in ['failed', 'error', 'denied']) else 'info'
            msg = re.sub(r'\[.*?\]', '', line).strip()
            if msg:
                events.append(self.make_event(ts, 'samba', 'smb_event', msg,
                    ip=ip, severity=sev))
        return events
