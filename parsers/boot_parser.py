import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

BOOT_PATTERN = re.compile(r'\[\s*(?P<status>OK|FAILED|WARNING)\s*\]\s*(?P<msg>.+)')


class BootLogParser(BaseParser):
    name          = 'boot'
    file_patterns = ['boot.log', 'boot.log.*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('boot.log')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        # boot.log traegt keine Timestamps — Datei-mtime statt Analysezeit
        # (Review-Fix: vorher bekam jeder Boot-Eintrag 'jetzt' als Zeit),
        # Suffix _ts_estimated macht die Schaetzung filterbar
        try:
            boot_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            boot_time = datetime.now(tz=timezone.utc)
        for line in self.read_lines(path):
            m = BOOT_PATTERN.search(line)
            if not m:
                continue
            status = m['status']
            sev = 'high' if status == 'FAILED' else 'medium' if status == 'WARNING' else 'info'
            events.append(self.make_event(
                boot_time, 'boot', f'boot_{status.lower()}_ts_estimated',
                f'Boot: [{status}] {m["msg"]}', severity=sev
            ))
        return events
