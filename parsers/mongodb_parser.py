import json
import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

MONGO_OLD = re.compile(
    r'^(?P<ts>\S+)\s+(?P<sev>[IWEF])\s+(?P<component>\S+)'
    r'\s+\[(?P<ctx>[^\]]+)\]\s+(?P<msg>.+)$'
)
LEVEL_MAP = {'I':'info','W':'medium','E':'high','F':'critical'}


class MongoDBParser(BaseParser):
    name          = 'mongodb'
    file_patterns = ['mongod.log', 'mongodb.log']

    def can_parse(self, path: Path) -> bool:
        return 'mongo' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            try:
                entry = json.loads(line)
                ts  = entry.get('t', {}).get('$date', '')
                msg = entry.get('msg', '')
                sev = entry.get('s', 'I')
                events.append(self.make_event(
                    ts, 'mongodb', 'db_event', str(msg),
                    severity=LEVEL_MAP.get(sev, 'info')
                ))
                continue
            except (json.JSONDecodeError, AttributeError):
                pass
            m = MONGO_OLD.match(line)
            if m:
                events.append(self.make_event(
                    m['ts'], 'mongodb', 'db_event', m['msg'],
                    severity=LEVEL_MAP.get(m['sev'], 'info')
                ))
        return events
