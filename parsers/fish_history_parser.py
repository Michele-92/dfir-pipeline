import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

CMD_RE = re.compile(r'^- cmd:\s+(.+)$')
TS_RE  = re.compile(r'^\s+when:\s+(\d+)$')
SUSPICIOUS = ['wget', 'curl', 'nc ', 'ncat', 'bash -i', 'python -c',
              'perl -e', 'chmod +x', 'base64', 'sudo su', '/tmp/']


class FishHistoryParser(BaseParser):
    name          = 'fish_history'
    file_patterns = ['fish_history']

    def can_parse(self, path: Path) -> bool:
        return 'fish_history' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        lines  = self.read_lines(path)
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(tz=timezone.utc)
        i = 0
        while i < len(lines):
            mc = CMD_RE.match(lines[i])
            if mc:
                cmd = mc.group(1).strip()
                ts, estimated = mtime, True
                if i + 1 < len(lines):
                    mt = TS_RE.match(lines[i + 1])
                    if mt:
                        try:
                            ts = datetime.fromtimestamp(int(mt.group(1)), tz=timezone.utc)
                            estimated = False
                        except (ValueError, OSError):
                            pass
                        i += 1
                sev = 'high' if any(s in cmd.lower() for s in SUSPICIOUS) else 'info'
                etype = 'shell_command_ts_estimated' if estimated else 'shell_command'
                events.append(self.make_event(
                    ts, 'fish_history', etype, cmd,
                    process='fish', severity=sev
                ))
            i += 1
        return events
