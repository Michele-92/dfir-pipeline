import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

PACMAN_PATTERN = re.compile(r'^\[(?P<ts>[^\]]+)\]\s+\[(?P<actor>\w+)\]\s+(?P<msg>.+)$')


class PacmanParser(BaseParser):
    name          = 'pacman'
    file_patterns = ['pacman.log']

    def can_parse(self, path: Path) -> bool:
        return 'pacman' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = PACMAN_PATTERN.match(line)
            if not m:
                continue
            events.append(self.make_event(
                m['ts'], 'pacman', 'pkg_operation', m['msg'], severity='info'
            ))
        return events
