import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

PG_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \w+)'
    r'\s+\[(?P<pid>\d+)\](?:\s+(?P<user>\S+))?\s+(?P<level>\w+):\s+(?P<msg>.+)$'
)
LEVEL_MAP = {'ERROR':'high','FATAL':'critical','PANIC':'critical',
             'WARNING':'medium','LOG':'info','INFO':'info'}


class PostgreSQLParser(BaseParser):
    name          = 'postgresql'
    file_patterns = ['postgresql-*.log']

    def can_parse(self, path: Path) -> bool:
        return 'postgresql' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = PG_PATTERN.match(line)
            if not m:
                continue
            events.append(self.make_event(
                m['ts'], 'postgresql', 'db_event', m['msg'],
                user=m.group('user'),
                severity=LEVEL_MAP.get(m['level'], 'info')
            ))
        return events
