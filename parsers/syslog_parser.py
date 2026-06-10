import gzip
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$'
)


class SyslogParser(BaseParser):
    name          = 'syslog'
    file_patterns = ['syslog', 'syslog.*', 'messages', 'messages-*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('syslog', 'messages'))

    def parse(self, path: Path) -> List[ForensicEvent]:
        from utils.timestamp import infer_syslog_year, year_reference
        events = []
        lines = self._read(path)
        ref = year_reference(path)   # Review-Fix #7: nicht datetime.now().year
        for line in lines:
            m = PATTERN.match(line)
            if not m:
                continue
            year = infer_syslog_year(ref, m['month'], int(m['day']))
            raw_ts = f'{year} {m["month"]} {m["day"]} {m["time"]}'
            events.append(self.make_event(
                timestamp  = raw_ts,
                source     = 'syslog',
                event_type = 'system',
                message    = m['msg'],
                process    = m['process'],
                severity   = self._detect_severity(m['msg']),
                raw        = m.groupdict(),
            ))
        return events

    def _read(self, path: Path) -> List[str]:
        if path.suffix == '.gz':
            with gzip.open(path, 'rt', errors='replace') as f:
                return f.read().splitlines()
        return self.read_lines(path)

    def _detect_severity(self, msg: str) -> str:
        lower = msg.lower()
        if any(w in lower for w in ['error', 'fail', 'critical', 'emerg', 'alert']):
            return 'high'
        if any(w in lower for w in ['warn', 'warning']):
            return 'medium'
        return 'info'
