import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

MYSQL_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)'
    r'\s+\d+\s+\[(?P<level>\w+)\]\s+(?P<msg>.+)$'
)
LEVEL_MAP = {'ERROR':'high','WARNING':'medium','NOTE':'info','System':'info'}


class MySQLErrorParser(BaseParser):
    name          = 'mysql'
    file_patterns = ['mysql/error.log', 'mysql.log']

    def can_parse(self, path: Path) -> bool:
        return 'mysql' in str(path).lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = MYSQL_PATTERN.match(line)
            if not m:
                continue
            events.append(self.make_event(
                m['ts'], 'mysql', 'db_event', m['msg'],
                severity=LEVEL_MAP.get(m['level'], 'info')
            ))
        return events
