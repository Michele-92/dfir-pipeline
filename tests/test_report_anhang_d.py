"""Test fuer Punkt 6 — Anhang D (Pipeline-Ausfuehrungsprotokoll).

Prueft, dass die ergaenzten Stage-Panels im PDF erscheinen:
Stage 01, 03, 03.5 (Basic Checks), 05, 08, 08.6 (Konsistenzpruefung),
13 und 14.
"""
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
pytest.importorskip('pypdf')
pytest.importorskip('reportlab')

from pypdf import PdfReader

from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from stages.report_modern import build_modern_report


def _text():
    case = Path(tempfile.mkdtemp()) / 'case'
    case.mkdir()
    # Ausgabedateien existieren real VOR dem Report (Stage 14 schreibt sie zuerst)
    for fn in ('iocs.xlsx', 'reboot_sessions.xlsx', 'activity_timeline.csv', 'pipeline_report.json'):
        (case / fn).write_text('x')
    ctx = PipelineContext(case_dir=case, combined_case=False)
    ctx.file_type = 'E01'; ctx.file_size_gb = 12.4; ctx.hash_source = 'E01-eingebettet'
    ctx.os_name = 'Ubuntu 22.04'; ctx.os_family = 'debian'; ctx.hostname = 'host01'
    ctx.kernel_version = '5.15'; ctx.machine_id = 'a1b2' * 8
    ctx.partition_profiles = [{
        'is_primary': True, 'partition_index': 2, 'offset': 2048,
        'os_name': 'Ubuntu 22.04', 'kernel_version': '5.15', 'hostname': 'host01',
        'install_time': '2022-11-28 14:22 UTC',
        'usage_period': {'first_activity': '2023-01-01', 'last_activity': '2023-03-07'},
        'ip_addresses': ['10.0.0.5'], 'virtualization': 'VMware',
        'ssh_config': {'permit_root_login': 'yes', 'password_auth': 'yes'},
        'enabled_services': ['ssh', 'cron'], 'users': [{'name': 'root'}, {'name': 'admin'}],
    }]
    ctx.basic_checks = [
        {'service': 'auth', 'log_path': '/var/log/auth.log', 'expected': True,
         'found': True, 'status': 'OK', 'anomaly_type': ''},
        {'service': 'syslog', 'log_path': '/var/log/syslog', 'expected': True,
         'found': False, 'status': 'FEHLT', 'anomaly_type': 'mandatory_missing'},
    ]
    ctx.tsk_log_files_extracted = 138
    ctx.tsk_deleted_found = 12; ctx.tsk_deleted_recovered = 9
    ctx.tsk_mactime_events = 142038; ctx.tsk_sorter_ran = True
    ctx.tsk_sorter_categories = {'exe': 1, 'archive': 2}
    ctx.normalized_events = [
        ForensicEvent(timestamp=datetime(2023, 3, 7, 9, 0, tzinfo=timezone.utc),
                      source='auth', event_type='ssh', message='Login',
                      severity='high', orig_path='/var/log/auth.log')]
    ctx.earliest_event = '2023-01-01 00:00:00 UTC'
    ctx.latest_event = '2023-03-07 12:00:00 UTC'
    ctx.consistency_checks = [
        {'check': 'leeres_log', 'image': '', 'service': 'syslog',
         'source_path': '/var/log/syslog', 'detail': 'Datei extrahiert aber 0 Events',
         'severity': 'high', 'anomaly': True}]
    ctx.consistency_anomalies = 1
    ctx.parser_stats = {'auth': 169, 'mactime': 142038}
    ctx.parsed_events = 142207
    ctx.stage_status = {'quality': 'SEHR GUT'}
    ctx.stage_errors = {}
    build_modern_report(ctx, case)
    pdf = case / 'forensischer_analysebericht.pdf'
    assert pdf.exists()
    return '\n'.join(p.extract_text() for p in PdfReader(str(pdf)).pages)


def test_anhang_d_panels_vorhanden():
    txt = _text()
    assert 'Stage 01' in txt
    assert 'Stage 03' in txt
    assert 'Basic Checks' in txt
    assert 'TSK-Extraktion' in txt
    assert 'Datennormalisierung' in txt
    assert 'Konsistenz' in txt
    assert 'Stage 13' in txt
    assert 'Stage 14' in txt


def test_anhang_d_konsistenz_quelle():
    txt = _text()
    assert '/var/log/syslog' in txt
