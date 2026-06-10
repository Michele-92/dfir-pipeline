import re
from datetime import datetime
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

KERN_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+\S+\s+kernel:\s+(?:\[\s*[\d.]+\]\s*)?(?P<msg>.+)$'
)
KERN_CRITICAL = ['oom','killed process','out of memory','panic','call trace',
                 'segfault','oops','bug:','hardware error','mce:']


class KernLogParser(BaseParser):
    name          = 'kern'
    file_patterns = ['kern.log', 'kern.log.*', 'dmesg']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('kern.log', 'dmesg'))

    def parse(self, path: Path) -> List[ForensicEvent]:
        from utils.timestamp import infer_syslog_year, year_reference
        events = []
        ref = year_reference(path)
        for line in self.read_lines(path):
            m = KERN_PATTERN.match(line)
            if not m:
                continue
            year = infer_syslog_year(ref, m['month'], int(m['day']))
            msg = m['msg']
            sev = 'high' if any(k in msg.lower() for k in KERN_CRITICAL) else 'info'
            events.append(self.make_event(
                f'{year} {m["month"]} {m["day"]} {m["time"]}',
                'kernel', 'kernel_event', msg, severity=sev
            ))
        return events
