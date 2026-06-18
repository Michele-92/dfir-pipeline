"""Tests fuer Stage 8.6 — Konsistenzpruefung (Event-Korroboration).

Prueft die zwei Kernchecks an synthetischen Events/Basic-Checks:
  C1  Paket-Korroboration (Log-ohne-Installation bestaetigt / entschaerft)
  C2  Leeres Log (Datei vorhanden, aber 0 geparste Events)
"""
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from utils.event_store import EventStore
from stages import stage086_consistency


def _build_db(tmp_path: Path) -> Path:
    db = tmp_path / 'events.db'
    events = [
        # auth.log hat echte Events -> kein "leeres Log"
        ForensicEvent(datetime(2023, 3, 7, 14, 2, 0), 'auth', 'ssh_login_success',
                      'Accepted password for root', orig_path='/var/log/auth.log'),
        # dpkg-Installations-Event fuer apache2 -> Korroboration
        ForensicEvent(datetime(2023, 3, 1, 9, 0, 0), 'dpkg', 'pkg_install',
                      'Paket install: apache2 Version=2.4.52', orig_path='/var/log/dpkg.log'),
        # nginx access.log hat Events, aber KEIN nginx-Install-Event
        ForensicEvent(datetime(2023, 3, 8, 10, 0, 0), 'nginx_access', 'http_request',
                      'GET / 200', orig_path='/var/log/nginx/access.log'),
        ForensicEvent(datetime(2023, 3, 8, 10, 0, 0), 'apache_access', 'http_request',
                      'GET /x 200', orig_path='/var/log/apache2/access.log'),
    ]
    with EventStore(db) as store:
        store.insert_events(events)
    return db


def _ctx(tmp_path: Path) -> PipelineContext:
    ctx = PipelineContext()
    ctx.events_db_path = _build_db(tmp_path)
    ctx.os_family = 'debian'
    ctx.basic_checks = [
        # vorhanden + Events -> keine Anomalie
        {'service': 'auth', 'log_path': '/var/log/auth.log',
         'expected': True, 'found': True, 'anomaly_type': ''},
        # vorhanden, aber KEINE Events -> C2 leeres_log (Pflicht -> high)
        {'service': 'syslog', 'log_path': '/var/log/syslog',
         'expected': True, 'found': True, 'anomaly_type': ''},
        # Log ohne Installation, KEIN nginx-Install-Event -> C1 bestaetigt
        {'service': 'nginx  (access.log)', 'log_path': '/var/log/nginx/access.log',
         'expected': False, 'found': True, 'anomaly_type': 'log_without_install'},
        # Log ohne Installation, ABER apache2-Install-Event -> C1 entschaerft
        {'service': 'apache2  (access.log)', 'log_path': '/var/log/apache2/access.log',
         'expected': False, 'found': True, 'anomaly_type': 'log_without_install'},
    ]
    return ctx


def test_c2_leeres_log(tmp_path):
    ctx = stage086_consistency.run(_ctx(tmp_path))
    leer = [c for c in ctx.consistency_checks if c['check'] == 'leeres_log']
    assert len(leer) == 1
    assert leer[0]['service'] == 'syslog'
    assert leer[0]['severity'] == 'high'      # Pflicht-Log
    assert leer[0]['anomaly'] is True
    assert leer[0]['source_path'] == '/var/log/syslog'   # nachpruefbare Quelle


def test_c1_log_ohne_installation_bestaetigt(tmp_path):
    ctx = stage086_consistency.run(_ctx(tmp_path))
    conf = [c for c in ctx.consistency_checks if c['check'] == 'log_ohne_installation']
    assert len(conf) == 1
    assert 'nginx' in conf[0]['service']
    assert conf[0]['anomaly'] is True


def test_c1_korroboration_entschaerft(tmp_path):
    ctx = stage086_consistency.run(_ctx(tmp_path))
    ok = [c for c in ctx.consistency_checks if c['check'] == 'paket_korroboration']
    assert len(ok) == 1
    assert 'apache2' in ok[0]['service']
    assert ok[0]['anomaly'] is False          # belegt -> kein Alarm


def test_anomalie_zahl(tmp_path):
    ctx = stage086_consistency.run(_ctx(tmp_path))
    # genau 2 echte Anomalien: leeres syslog + nginx ohne Install
    assert ctx.consistency_anomalies == 2


def test_keine_db_ueberspringt(tmp_path):
    ctx = PipelineContext()
    ctx.events_db_path = tmp_path / 'fehlt.db'
    ctx.basic_checks = [{'service': 'auth', 'log_path': '/var/log/auth.log',
                         'expected': True, 'found': True, 'anomaly_type': ''}]
    ctx = stage086_consistency.run(ctx)
    assert ctx.consistency_checks == []
    assert ctx.consistency_anomalies == 0
    assert 'UEBERSPRUNGEN' in ctx.stage_status.get('stage_08_6', '')
