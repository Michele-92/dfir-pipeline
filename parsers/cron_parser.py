import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser
from parsers.syslog_parser import PATTERN as SYSLOG_PATTERN

CRON_CMD = re.compile(r'CMD\s+\((.+)\)')
SUSPICIOUS_CMDS = ['wget', 'curl', 'nc ', 'ncat', 'bash -i', '/tmp/', 'python -c',
                   'perl -e', 'ruby -e', 'base64', 'chmod +x']


class CronParser(BaseParser):
    name          = 'cron'
    file_patterns = ['cron', 'cron.log', 'cron.*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('cron')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        year = datetime.now().year
        for line in self.read_lines(path):
            m_base = SYSLOG_PATTERN.match(line)
            if not m_base:
                continue
            msg = m_base['msg']
            ts  = f'{year} {m_base["month"]} {m_base["day"]} {m_base["time"]}'
            mc  = CRON_CMD.search(msg)
            if mc:
                cmd = mc.group(1)
                sev = 'high' if any(s in cmd.lower() for s in SUSPICIOUS_CMDS) else 'info'
                events.append(self.make_event(
                    ts, 'cron', 'cron_cmd', f'Cron CMD: {cmd}',
                    process='cron', severity=sev
                ))
            else:
                events.append(self.make_event(
                    ts, 'cron', 'cron_event', msg,
                    process=m_base['process'], severity='info'
                ))
        return events
