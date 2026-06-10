import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

APACHE_CLF = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?$'
)
SUSPICIOUS_PATHS = ['/etc/passwd', '/etc/shadow', '../', '..%2f',
                    'wp-admin', 'phpmyadmin', '/.env', '/.git',
                    '/shell', '/cmd', 'exec(', 'union select']


class ApacheAccessParser(BaseParser):
    name          = 'apache_access'
    file_patterns = ['access.log', 'access_log', 'other_vhosts_access.log']

    def can_parse(self, path: Path) -> bool:
        return 'access' in path.name and path.suffix in ('', '.log', '.1')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = APACHE_CLF.match(line)
            if not m:
                continue
            status   = int(m['status'])
            path_req = m['path']
            if status >= 500:
                sev = 'high'
            elif status >= 400:
                sev = 'medium'
            elif any(s in path_req.lower() for s in SUSPICIOUS_PATHS):
                sev = 'high'
            else:
                sev = 'info'
            # CLF-Format '10/Oct/2000:13:55:36 -0700' ist fuer dateutil
            # unparsebar (verifiziert) -> explizites strptime
            try:
                ts = datetime.strptime(m['ts'], '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                ts = m['ts']
            events.append(self.make_event(
                ts, 'apache_access', 'http_request',
                f'{m["method"]} {path_req} → {status}',
                ip=m['ip'], severity=sev,
                raw={'method': m['method'], 'path': path_req, 'status': status}
            ))
        return events
