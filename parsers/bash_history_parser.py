import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

TS_LINE = re.compile(r'^#(\d+)$')
SUSPICIOUS = ['wget', 'curl', 'nc ', 'ncat', 'bash -i', 'python -c',
              'perl -e', 'chmod +x', 'base64', 'sudo su', '/tmp/']


class BashHistoryParser(BaseParser):
    name          = 'bash_history'
    file_patterns = ['.bash_history']

    def can_parse(self, path: Path) -> bool:
        return 'bash_history' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        lines  = self.read_lines(path)
        # Ohne HISTTIMEFORMAT gibt es keine Zeiten — Datei-mtime als
        # Schaetzung (statt Analysezeit) + _ts_estimated-Kennzeichnung
        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            ts = datetime.now(tz=timezone.utc)
        estimated = True
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            m = TS_LINE.match(line)
            if m:
                try:
                    ts = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
                    estimated = False
                except (ValueError, OSError):
                    pass
                i += 1
                if i < len(lines):
                    cmd = lines[i].strip()
                    i += 1
                else:
                    continue
            else:
                cmd = line
                i += 1
            if not cmd:
                continue
            sev = 'high' if any(s in cmd.lower() for s in SUSPICIOUS) else 'info'
            etype = 'shell_command_ts_estimated' if estimated else 'shell_command'
            events.append(self.make_event(
                ts, 'bash_history', etype, cmd,
                process='bash', severity=sev
            ))
        return events
