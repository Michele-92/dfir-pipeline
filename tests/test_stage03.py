import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.pipeline_context import PipelineContext
from stages.stage06_logs import route_and_parse, run


def test_route_syslog():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / 'syslog'
        p.write_text('Apr 22 09:15:33 host proc[1]: test message\n')
        events = route_and_parse(p)
        assert len(events) == 1
        assert events[0].source == 'syslog'


def test_route_auth_log():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / 'auth.log'
        p.write_text(
            'Apr 22 09:15:33 host sshd[1]: Accepted password for alice from 10.0.0.1 port 22\n'
        )
        events = route_and_parse(p)
        ssh = [e for e in events if 'ssh' in e.event_type]
        assert len(ssh) >= 1


def test_stage03_with_log_dir():
    with tempfile.TemporaryDirectory() as tmp:
        log_dir = Path(tmp) / 'logs'
        log_dir.mkdir()
        (log_dir / 'syslog').write_text(
            'Apr 22 09:15:33 host sshd[1]: test\n' * 5
        )
        ctx = PipelineContext(logs_dir_path=log_dir)
        ctx = run(ctx)
        assert ctx.parsed_events > 0
        assert ctx.total_log_lines > 0


def test_stage03_empty_dir():
    with tempfile.TemporaryDirectory() as tmp:
        ctx = PipelineContext(logs_dir_path=Path(tmp))
        ctx = run(ctx)
        assert ctx.parsed_events == 0
