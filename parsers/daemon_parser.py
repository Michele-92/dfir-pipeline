from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.syslog_parser import SyslogParser


class DaemonLogParser(SyslogParser):
    name          = 'daemon'
    file_patterns = ['daemon.log', 'daemon.log.*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('daemon.log')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = super().parse(path)
        for e in events:
            e.source     = 'daemon'
            e.event_type = 'daemon_event'
        return events
