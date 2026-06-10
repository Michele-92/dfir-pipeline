import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

YUM_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+(?P<action>\S+):\s+(?P<pkg>.+)$'
)


class YumParser(BaseParser):
    name          = 'yum'
    file_patterns = ['yum.log', 'yum.log-*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('yum.log')

    def parse(self, path: Path) -> List[ForensicEvent]:
        from utils.timestamp import infer_syslog_year, year_reference
        events = []
        ref = year_reference(path)
        for line in self.read_lines(path):
            m = YUM_PATTERN.match(line)
            if not m:
                continue
            year = infer_syslog_year(ref, m['month'], int(m['day']))
            events.append(self.make_event(
                f'{year} {m["month"]} {m["day"]} {m["time"]}',
                'yum', f'pkg_{m["action"].lower()}',
                f'YUM {m["action"]}: {m["pkg"]}',
                severity='info'
            ))
        return events
