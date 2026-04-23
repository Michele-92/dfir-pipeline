import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

NGINX_ERR = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+\[(?P<level>\w+)\]\s+\d+#\d+:\s+(?P<msg>.+)$'
)
LEVEL_MAP = {'emerg':'critical','alert':'critical','crit':'high',
             'error':'high','warn':'medium','notice':'info','info':'info'}


class NginxErrorParser(BaseParser):
    name          = 'nginx_error'
    file_patterns = ['nginx/error.log']

    def can_parse(self, path: Path) -> bool:
        return 'nginx' in str(path).lower() and 'error' in path.name

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = NGINX_ERR.match(line)
            if not m:
                continue
            events.append(self.make_event(
                m['ts'], 'nginx_error', 'http_error', m['msg'],
                severity=LEVEL_MAP.get(m['level'].lower(), 'info')
            ))
        return events
