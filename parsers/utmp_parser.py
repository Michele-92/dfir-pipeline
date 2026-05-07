from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.wtmp_parser import WtmpParser


class UtmpParser(WtmpParser):
    name          = 'utmp'
    file_patterns = ['utmp']

    def can_parse(self, path: Path) -> bool:
        return 'utmp' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = super().parse(path)
        for e in events:
            e.source = 'utmp'
        return events
