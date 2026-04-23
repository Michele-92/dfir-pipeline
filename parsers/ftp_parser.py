import re
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

FTP_PATTERN = re.compile(
    r'^(?P<ts>\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
    r'\s+\[pid\s+\d+\]\s+(?P<msg>.+)$'
)
FTP_LOGIN  = re.compile(r'OK LOGIN:\s+Client\s+"([\d.]+)"')
FTP_UPLOAD = re.compile(r'OK UPLOAD:\s+Client\s+"([\d.]+)".*?"/(.+?)"')
FTP_FAIL   = re.compile(r'FAIL LOGIN:\s+Client\s+"([\d.]+)"')


class FTPParser(BaseParser):
    name          = 'ftp'
    file_patterns = ['vsftpd.log', 'proftpd.log', 'ftp.log']

    def can_parse(self, path: Path) -> bool:
        return any(x in path.name.lower() for x in ['vsftpd', 'proftpd', 'ftp'])

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            ts_m = re.search(
                r'(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line
            )
            ts = ts_m.group('ts') if ts_m else ''
            ml = FTP_LOGIN.search(line)
            if ml:
                events.append(self.make_event(ts, 'ftp', 'ftp_login',
                    f'FTP Login OK von {ml.group(1)}', ip=ml.group(1), severity='medium'))
                continue
            mu = FTP_UPLOAD.search(line)
            if mu:
                events.append(self.make_event(ts, 'ftp', 'ftp_upload',
                    f'FTP Upload von {mu.group(1)}: /{mu.group(2)}',
                    ip=mu.group(1), severity='medium'))
                continue
            mf = FTP_FAIL.search(line)
            if mf:
                events.append(self.make_event(ts, 'ftp', 'ftp_fail',
                    f'FTP Login FAIL von {mf.group(1)}', ip=mf.group(1), severity='high'))
        return events
