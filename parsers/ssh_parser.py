import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser
from parsers.syslog_parser import PATTERN as SYSLOG_PATTERN

SSH_ACCEPT  = re.compile(r'Accepted (password|publickey) for (\S+) from ([\d.]+)')
SSH_FAIL    = re.compile(r'Failed (password|publickey) for (\S+) from ([\d.]+)')
SSH_INVALID = re.compile(r'Invalid user (\S+) from ([\d.]+)')
SSH_TUNNEL  = re.compile(r'Received disconnect')
SSH_X11     = re.compile(r'X11 forwarding')


class SSHParser(BaseParser):
    name          = 'ssh'
    file_patterns = ['auth.log', 'secure']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('auth.log', 'secure'))

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        year = datetime.now().year
        for line in self.read_lines(path):
            if 'sshd' not in line:
                continue
            m_base = SYSLOG_PATTERN.match(line)
            if not m_base:
                continue
            msg = m_base['msg']
            ts  = f'{year} {m_base["month"]} {m_base["day"]} {m_base["time"]}'

            for pattern, etype, sev in [
                (SSH_ACCEPT,  'ssh_success', 'medium'),
                (SSH_FAIL,    'ssh_fail',    'high'),
                (SSH_INVALID, 'ssh_invalid', 'high'),
            ]:
                m = pattern.search(msg)
                if m:
                    events.append(self.make_event(
                        ts, 'ssh', etype, msg,
                        ip=m.group(3) if len(m.groups()) >= 3 else m.group(2),
                        severity=sev
                    ))
                    break
            else:
                if SSH_TUNNEL.search(msg) or SSH_X11.search(msg):
                    events.append(self.make_event(ts, 'ssh', 'ssh_misc', msg, severity='info'))
        return events
