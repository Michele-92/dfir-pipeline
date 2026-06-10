import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser
from parsers.syslog_parser import PATTERN

SSH_SUCCESS = re.compile(r'Accepted (password|publickey) for (\S+) from ([\d.]+)')
SSH_FAIL    = re.compile(r'Failed (password|publickey) for (\S+) from ([\d.]+)')
SSH_INVALID = re.compile(r'Invalid user (\S+) from ([\d.]+)')
SUDO_CMD    = re.compile(r'(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)')
NEW_USER    = re.compile(r'new user: name=(\S+)')
USER_DEL    = re.compile(r'delete user (.+)')
# uebernommen aus SSHParser (entfernt — kam durch Routing-Reihenfolge nie zum Zug)
SSH_MISC    = re.compile(r'Received disconnect|X11 forwarding')


class AuthLogParser(BaseParser):
    name          = 'auth'
    file_patterns = ['auth.log', 'auth.log.*', 'secure', 'secure-*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('auth.log', 'secure'))

    def parse(self, path: Path) -> List[ForensicEvent]:
        from utils.timestamp import infer_syslog_year, year_reference
        events = []
        ref = year_reference(path)
        for line in self.read_lines(path):
            m_base = PATTERN.match(line)
            if not m_base:
                continue
            msg  = m_base['msg']
            year = infer_syslog_year(ref, m_base['month'], int(m_base['day']))
            ts  = f'{year} {m_base["month"]} {m_base["day"]} {m_base["time"]}'

            m = SSH_SUCCESS.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'ssh_login_success',
                    f'SSH Login erfolgreich: User={m[2]} IP={m[3]} Methode={m[1]}',
                    user=m[2], ip=m[3], severity='medium'))
                continue

            m = SSH_FAIL.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'ssh_login_failed',
                    f'SSH Login fehlgeschlagen: User={m[2]} IP={m[3]}',
                    user=m[2], ip=m[3], severity='high'))
                continue

            m = SSH_INVALID.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'ssh_invalid_user',
                    f'Ungültiger SSH-User: {m[1]} von {m[2]}',
                    user=m[1], ip=m[2], severity='high'))
                continue

            m = SUDO_CMD.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'sudo_command',
                    f'Sudo: {m[1]} führte als {m[2]} aus: {m[3]}',
                    user=m[1], process='sudo', severity='medium'))
                continue

            m = NEW_USER.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'user_created',
                    f'Neuer Benutzer erstellt: {m[1]}',
                    user=m[1], severity='high'))
                continue

            m = USER_DEL.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'user_deleted',
                    f'Benutzer gelöscht: {m[1]}',
                    user=m[1].strip(), severity='high'))
                continue

            if 'sshd' in line and SSH_MISC.search(msg):
                events.append(self.make_event(ts, 'auth', 'ssh_misc',
                    msg, severity='info'))
        return events
