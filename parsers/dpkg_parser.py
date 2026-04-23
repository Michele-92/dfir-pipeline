import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

DPKG_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>\S+)\s+(?P<pkg>\S+)\s+(?P<ver>.+)$'
)
DPKG_SUSPICIOUS = ['netcat', 'nmap', 'hydra', 'john', 'hashcat',
                   'aircrack', 'metasploit', 'sqlmap', 'nikto']


class DpkgParser(BaseParser):
    name          = 'dpkg'
    file_patterns = ['dpkg.log', 'dpkg.log.*']

    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('dpkg.log')

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = DPKG_PATTERN.match(line)
            if not m:
                continue
            pkg = m['pkg']
            sev = 'high' if any(s in pkg.lower() for s in DPKG_SUSPICIOUS) else 'info'
            events.append(self.make_event(
                m['ts'], 'dpkg', f'pkg_{m["action"]}',
                f'Paket {m["action"]}: {pkg} Version={m["ver"]}',
                severity=sev, raw={'action': m['action'], 'package': pkg}
            ))
        return events
