import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

VPN_TS  = re.compile(r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})')
VPN_IP  = re.compile(r'([\d.]+):\d+')
VPN_CON = re.compile(r'(?:Peer Connection Initiated|CONNECTED|Authenticated)')
VPN_DIS = re.compile(r'(?:SIGTERM|process exiting|peer did not respond)')


class OpenVPNParser(BaseParser):
    name          = 'openvpn'
    file_patterns = ['openvpn.log', 'openvpn.log.*']

    def can_parse(self, path: Path) -> bool:
        return 'openvpn' in path.name.lower()

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            mt = VPN_TS.match(line)
            ts = mt.group('ts') if mt else ''
            mi = VPN_IP.search(line)
            ip = mi.group(1) if mi else None
            if VPN_CON.search(line):
                events.append(self.make_event(ts, 'openvpn', 'vpn_connect',
                    line.strip(), ip=ip, severity='medium'))
            elif VPN_DIS.search(line):
                events.append(self.make_event(ts, 'openvpn', 'vpn_disconnect',
                    line.strip(), ip=ip, severity='info'))
            elif 'error' in line.lower() or 'failed' in line.lower():
                events.append(self.make_event(ts, 'openvpn', 'vpn_error',
                    line.strip(), ip=ip, severity='high'))
        return events
