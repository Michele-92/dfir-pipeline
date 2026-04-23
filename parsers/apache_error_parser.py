import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

APACHE_ERR = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+\[(?P<module>[^:]+):(?P<level>\w+)\]'
    r'\s+\[pid\s+(?P<pid>\d+)\]\s+(?P<msg>.+)$'
)
LEVEL_MAP = {'emerg':'critical','alert':'critical','crit':'high',
             'error':'high','warn':'medium','notice':'info','info':'info'}


class ApacheErrorParser(BaseParser):
    name          = 'apache_error'
    file_patterns = ['error.log', 'error_log']

    def can_parse(self, path: Path) -> bool:
        return 'error' in path.name and 'apache' in str(path).lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = APACHE_ERR.match(line)
            if not m:
                continue
            events.append(self.make_event(
                m['ts'], 'apache_error', 'http_error', m['msg'],
                severity=LEVEL_MAP.get(m['level'].lower(), 'info')
            ))
        return events
