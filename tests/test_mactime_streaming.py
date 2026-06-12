"""Test fuer den mactime-Streaming-Parser (stage05_tsk).

Regression: mactime gibt das Datum nur in der ERSTEN Zeile einer
Zeitgruppe aus; Folgezeilen (auch m/a/c/b derselben Datei) haben ein
LEERES Datumsfeld. Diese wurden frueher verworfen -> in der Excel
erschien z.B. nur atime_UTC einer Datei, nie mtime/ctime/btime.
"""
import re
from datetime import datetime, timezone

# Identische Regexe wie in stage05_tsk._generate_mactime_streaming
DATE_RE = re.compile(r'^(?P<date>\w{3} \w{3}\s+\d+ \d{4} \d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$')
ROW_RE  = re.compile(r'^(?P<size>\d+)\s+(?P<macb>[macb\.]+)\s+(?P<mode>\S+)\s+'
                     r'(?P<uid>\d+)\s+(?P<gid>\d+)\s+(?P<inode>\S+)\s+(?P<filename>.+)$')


def _parse(mactime_output):
    events = []
    last_ts = None
    for line in mactime_output.splitlines():
        if not line or line.startswith('#'):
            continue
        dm = DATE_RE.match(line)
        if dm:
            last_ts = datetime.strptime(dm.group('date').strip(),
                                        '%a %b %d %Y %H:%M:%S').replace(tzinfo=timezone.utc)
            row = dm.group('rest')
        else:
            row = line.strip()
        if last_ts is None:
            continue
        m = ROW_RE.match(row.strip())
        if not m:
            continue
        events.append((last_ts, m.group('macb'), m.group('filename').strip()))
    return events


_SAMPLE = """Mon Nov 28 2022 14:22:40   1234 m.c. r/rrwxr-xr-x 0 0 5678   /etc/machine-id
                            512 .a.. r/rrwxr-xr-x 0 0 9012   /etc/hostname
Tue Nov 29 2022 09:00:00     33 ...b r/rrwxr-xr-x 0 0 5678   /etc/machine-id
                            128 .a.. r/rrwxr-xr-x 0 0 5678   /etc/machine-id
Wed Nov 30 2022 10:00:00    256 macb r/rrwxr-xr-x 0 0 4444   /etc/passwd"""


def test_leerdatum_folgezeilen_nicht_verworfen():
    assert len(_parse(_SAMPLE)) == 5   # nicht nur die 3 Zeilen mit Datum


def test_alle_macb_flags_pro_datei():
    flags = set()
    for ts, macb, fn in _parse(_SAMPLE):
        if fn == '/etc/machine-id':
            flags |= {c for c in 'macb' if c in macb}
    assert flags == {'m', 'a', 'c', 'b'}   # vorher nur {'a'}


def test_folgezeile_erbt_zeitstempel():
    ev = _parse(_SAMPLE)
    # /etc/hostname (.a.. Folgezeile) erbt 14:22:40 der Gruppe
    host = [e for e in ev if e[2] == '/etc/hostname'][0]
    assert host[0] == datetime(2022, 11, 28, 14, 22, 40, tzinfo=timezone.utc)
