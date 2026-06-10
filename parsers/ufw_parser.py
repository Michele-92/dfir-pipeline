import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser
from parsers.syslog_parser import PATTERN as SYSLOG_PATTERN

UFW_RE = re.compile(
    r'\[UFW\s+(?P<action>BLOCK|ALLOW|LIMIT)\]\s+.*?SRC=(?P<src>[\d.]+).*?DST=(?P<dst>[\d.]+)'
)


class UFWParser(BaseParser):
    name          = 'ufw'
    file_patterns = ['ufw.log', 'ufw.log.*']

    def can_parse(self, path: Path) -> bool:
        return 'ufw' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        from utils.timestamp import infer_syslog_year, year_reference
        events = []
        ref = year_reference(path)
        for line in self.read_lines(path):
            m_base = SYSLOG_PATTERN.match(line)
            if not m_base:
                continue
            year = infer_syslog_year(ref, m_base['month'], int(m_base['day']))
            msg = m_base['msg']
            mu  = UFW_RE.search(msg)
            if not mu:
                continue
            action = mu['action']
            sev    = 'high' if action == 'BLOCK' else 'info'
            events.append(self.make_event(
                f'{year} {m_base["month"]} {m_base["day"]} {m_base["time"]}',
                'ufw', f'fw_{action.lower()}',
                f'UFW {action}: SRC={mu["src"]} DST={mu["dst"]}',
                ip=mu['src'], severity=sev
            ))
        return events
