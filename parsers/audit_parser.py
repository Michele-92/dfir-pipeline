import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

AUDIT_PATTERN = re.compile(
    r'^type=(?P<type>\S+)\s+msg=audit\((?P<ts>[\d.]+):\d+\):\s+(?P<msg>.+)$'
)
HIGH_TYPES = {'EXECVE', 'SYSCALL', 'USER_AUTH', 'USER_LOGIN', 'USER_CMD',
              'ADD_USER', 'DEL_USER', 'ADD_GROUP', 'DEL_GROUP'}


class AuditParser(BaseParser):
    name          = 'audit'
    file_patterns = ['audit/audit.log', 'audit.log']

    def can_parse(self, path: Path) -> bool:
        return 'audit' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = AUDIT_PATTERN.match(line)
            if not m:
                continue
            atype = m['type']
            try:
                from datetime import datetime, timezone
                ts = datetime.fromtimestamp(float(m['ts']), tz=timezone.utc)
            except (ValueError, OSError):
                ts = m['ts']
            sev = 'high' if atype in HIGH_TYPES else 'info'
            events.append(self.make_event(
                ts, 'audit', f'audit_{atype.lower()}', m['msg'],
                severity=sev, raw={'audit_type': atype}
            ))
        return events
