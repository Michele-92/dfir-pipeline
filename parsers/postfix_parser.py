import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser
from parsers.syslog_parser import PATTERN as SYSLOG_PATTERN

MAIL_FROM = re.compile(r'from=<([^>]+)>')
MAIL_TO   = re.compile(r'to=<([^>]+)>')
MAIL_STS  = re.compile(r'status=(\S+)')


class PostfixMailParser(BaseParser):
    name          = 'postfix'
    file_patterns = ['mail.log', 'maillog', 'mail.log.*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('mail.log', 'maillog'))

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        year = datetime.now().year
        for line in self.read_lines(path):
            m_base = SYSLOG_PATTERN.match(line)
            if not m_base:
                continue
            msg = m_base['msg']
            ts  = f'{year} {m_base["month"]} {m_base["day"]} {m_base["time"]}'
            mf  = MAIL_FROM.search(msg)
            mt  = MAIL_TO.search(msg)
            ms  = MAIL_STS.search(msg)
            sev = 'high' if ms and ms.group(1) in ('bounced', 'deferred') else 'info'
            events.append(self.make_event(
                ts, 'postfix', 'mail_event',
                f'Mail: {msg[:200]}',
                severity=sev,
                raw={
                    'from':   mf.group(1) if mf else '',
                    'to':     mt.group(1) if mt else '',
                    'status': ms.group(1) if ms else '',
                }
            ))
        return events
