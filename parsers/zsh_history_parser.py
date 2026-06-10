import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

ZSH_EXTENDED = re.compile(r'^: (\d+):\d+;(.+)$')
SUSPICIOUS = ['wget', 'curl', 'nc ', 'ncat', 'bash -i', 'python -c',
              'perl -e', 'chmod +x', 'base64', 'sudo su', '/tmp/']


class ZshHistoryParser(BaseParser):
    name          = 'zsh_history'
    file_patterns = ['.zsh_history']

    def can_parse(self, path: Path) -> bool:
        return 'zsh_history' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(tz=timezone.utc)
        for line in self.read_lines(path):
            m = ZSH_EXTENDED.match(line)
            estimated = False
            if m:
                try:
                    ts = datetime.fromtimestamp(int(m.group(1)), tz=timezone.utc)
                except (ValueError, OSError):
                    ts, estimated = mtime, True
                cmd = m.group(2).strip()
            else:
                ts, estimated = mtime, True
                cmd = line.strip()
            if not cmd:
                continue
            sev = 'high' if any(s in cmd.lower() for s in SUSPICIOUS) else 'info'
            etype = 'shell_command_ts_estimated' if estimated else 'shell_command'
            events.append(self.make_event(
                ts, 'zsh_history', etype, cmd,
                process='zsh', severity=sev
            ))
        return events
