import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

F2B_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+'
    r'fail2ban\.\S+\s+\[(?P<pid>\d+)\]\s+(?P<level>\w+)\s+(?P<msg>.+)$'
)
BAN_RE   = re.compile(r'Ban\s+([\d.]+)')
UNBAN_RE = re.compile(r'Unban\s+([\d.]+)')


class Fail2BanParser(BaseParser):
    name          = 'fail2ban'
    file_patterns = ['fail2ban.log', 'fail2ban.log.*']

    def can_parse(self, path: Path) -> bool:
        return 'fail2ban' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = F2B_PATTERN.match(line)
            if not m:
                continue
            msg = m['msg']
            ip  = None
            sev = 'info'
            mb = BAN_RE.search(msg)
            if mb:
                ip  = mb.group(1)
                sev = 'high'
            mu = UNBAN_RE.search(msg)
            if mu:
                ip  = mu.group(1)
                sev = 'medium'
            events.append(self.make_event(
                m['ts'], 'fail2ban', 'ban_event', msg,
                ip=ip, severity=sev
            ))
        return events
