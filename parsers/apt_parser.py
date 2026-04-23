import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser


class AptHistoryParser(BaseParser):
    name          = 'apt'
    file_patterns = ['history.log', 'history.log.*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('history.log')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        try:
            content = path.read_text(errors='replace')
        except PermissionError:
            return []
        for block in content.split('\n\n'):
            ts_m  = re.search(r'Start-Date:\s*(.+)', block)
            cmd_m = re.search(r'Commandline:\s*(.+)', block)
            if not ts_m:
                continue
            ts  = ts_m.group(1).strip()
            cmd = cmd_m.group(1).strip() if cmd_m else ''
            events.append(self.make_event(
                ts, 'apt', 'apt_operation',
                f'APT Befehl: {cmd}',
                process='apt', severity='info'
            ))
        return events
