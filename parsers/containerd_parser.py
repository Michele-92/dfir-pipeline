import json
import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

CONTAINERD_RE = re.compile(
    r'^time="(?P<ts>[^"]+)"\s+level=(?P<level>\w+)\s+msg="(?P<msg>[^"]+)"'
)


class ContainerdParser(BaseParser):
    name          = 'containerd'
    file_patterns = ['containerd.log']

    def can_parse(self, path: Path) -> bool:
        return 'containerd' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {'error':'high','warning':'medium','warn':'medium',
                     'info':'info','debug':'info'}
        for line in self.read_lines(path):
            try:
                entry = json.loads(line)
                ts  = entry.get('time', entry.get('ts', ''))
                msg = entry.get('msg', '')
                lvl = entry.get('level', 'info').lower()
            except (json.JSONDecodeError, AttributeError):
                m = CONTAINERD_RE.match(line)
                if not m:
                    continue
                ts, lvl, msg = m['ts'], m['level'].lower(), m['msg']
            if not msg:
                continue
            events.append(self.make_event(
                ts, 'containerd', 'runtime_event', msg,
                severity=LEVEL_MAP.get(lvl, 'info')
            ))
        return events
