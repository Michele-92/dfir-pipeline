import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.event import ForensicEvent
from models.pipeline_context import PipelineContext
from utils.event_store import EventStore
from stages.stage07_ioc import run, _collect_texts


def _ctx_with_events(messages):
    # Stage 07 liest Events seit der DuckDB-Migration aus events.db
    # (ctx.events wird in Stage 06 geleert) — Tests muessen daher wie die
    # echte Pipeline in eine events.db schreiben.
    ctx = PipelineContext()
    events = [
        ForensicEvent(
            timestamp  = datetime.now(tz=timezone.utc),
            source     = 'test',
            event_type = 'test',
            message    = msg,
        )
        for msg in messages
    ]
    db_path = Path(tempfile.mkdtemp()) / 'events.db'
    with EventStore(db_path) as store:
        store.insert_events(events)
    ctx.events_db_path = db_path
    return ctx


def test_ip_extraction():
    ctx = _ctx_with_events(['Connection from 192.168.1.99 blocked'])
    ctx = run(ctx)
    ips = [i for i in ctx.iocs if i.type == 'ip']
    assert any(i.value == '192.168.1.99' for i in ips)


def test_domain_extraction():
    ctx = _ctx_with_events(['DNS query to evil.example.com resolved'])
    ctx = run(ctx)
    domains = [i for i in ctx.iocs if i.type == 'domain']
    assert any('evil.example.com' in i.value for i in domains)


def test_md5_extraction():
    ctx = _ctx_with_events(['File hash: d41d8cd98f00b204e9800998ecf8427e'])
    ctx = run(ctx)
    hashes = [i for i in ctx.iocs if i.type == 'hash_md5']
    assert len(hashes) >= 1


def test_cve_extraction():
    ctx = _ctx_with_events(['Exploit for CVE-2021-44228 detected'])
    ctx = run(ctx)
    cves = [i for i in ctx.iocs if i.type == 'cve']
    assert any(i.value == 'CVE-2021-44228' for i in cves)


def test_email_extraction():
    ctx = _ctx_with_events(['Email from attacker@evil.com received'])
    ctx = run(ctx)
    emails = [i for i in ctx.iocs if i.type == 'email']
    assert any(i.value == 'attacker@evil.com' for i in emails)


def test_no_duplicates():
    ctx = _ctx_with_events([
        'IP 1.2.3.4 connected',
        'IP 1.2.3.4 connected again',
    ])
    ctx = run(ctx)
    ips = [i for i in ctx.iocs if i.value == '1.2.3.4']
    assert len(ips) == 1


def test_tsk_fallback_lowers_quality():
    ctx = _ctx_with_events(['test'])
    ctx.tsk_fallback_used = True
    ctx = run(ctx)
    assert ctx.ioc_quality == 'MITTEL'
