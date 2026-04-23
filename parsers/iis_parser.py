import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

SUSPICIOUS_PATHS = ['/etc/passwd', '../', '..%2f', 'cmd.exe', 'powershell',
                    '/.env', '/.git', 'union+select', 'exec(']


class IISLogParser(BaseParser):
    name          = 'iis'
    file_patterns = ['u_ex*.log']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('u_ex') and path.suffix == '.log'

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        fields = []
        for line in self.read_lines(path):
            if line.startswith('#Fields:'):
                fields = line[8:].strip().split()
                continue
            if line.startswith('#'):
                continue
            parts = line.split()
            if not fields or len(parts) < len(fields):
                continue
            row = dict(zip(fields, parts))
            ts  = f'{row.get("date","")} {row.get("time","")}'
            cs_uri = row.get('cs-uri-stem', '')
            status = row.get('sc-status', '200')
            ip     = row.get('c-ip', '')
            try:
                st = int(status)
            except ValueError:
                st = 200
            if st >= 500:
                sev = 'high'
            elif st >= 400:
                sev = 'medium'
            elif any(s in cs_uri.lower() for s in SUSPICIOUS_PATHS):
                sev = 'high'
            else:
                sev = 'info'
            events.append(self.make_event(
                ts, 'iis', 'http_request',
                f'{row.get("cs-method","GET")} {cs_uri} → {status}',
                ip=ip, severity=sev,
                raw={'status': status, 'path': cs_uri}
            ))
        return events
