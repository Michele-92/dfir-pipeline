from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.apache_access_parser import ApacheAccessParser


class NginxAccessParser(ApacheAccessParser):
    name          = 'nginx_access'
    file_patterns = ['nginx/access.log', 'nginx/access.log.*']

    def can_parse(self, path: Path) -> bool:
        return 'nginx' in str(path).lower() and 'access' in path.name

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = super().parse(path)
        for e in events:
            e.source = 'nginx_access'
        return events
