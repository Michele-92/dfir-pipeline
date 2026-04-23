import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

DNF_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})'
    r'\s+(?P<level>\w+)\s+(?P<msg>.+)$'
)


class DnfParser(BaseParser):
    name          = 'dnf'
    file_patterns = ['dnf.log', 'dnf.rpm.log']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('dnf')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = DNF_PATTERN.match(line)
            if not m:
                continue
            events.append(self.make_event(
                m['ts'], 'dnf', 'pkg_operation', m['msg'], severity='info'
            ))
        return events
