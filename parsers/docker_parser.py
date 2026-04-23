import json
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser


class DockerParser(BaseParser):
    name          = 'docker'
    file_patterns = ['containers/*-json.log']

    def can_parse(self, path: Path) -> bool:
        return path.suffix == '.log' and 'containers' in str(path).lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            try:
                entry = json.loads(line)
                ts    = entry.get('time', '')
                msg   = entry.get('log', '').strip()
                stream = entry.get('stream', 'stdout')
                if not msg:
                    continue
                sev = 'high' if any(w in msg.lower() for w in ['error', 'fatal', 'panic']) else 'info'
                events.append(self.make_event(
                    ts, 'docker', 'container_log', msg,
                    severity=sev, raw={'stream': stream}
                ))
            except (json.JSONDecodeError, AttributeError):
                continue
        return events
