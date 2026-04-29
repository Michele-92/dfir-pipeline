import subprocess
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)


def run(ctx: PipelineContext, force: bool = False, skip: bool = False) -> PipelineContext:
    should_run, reason = should_run_autopsy(ctx, force, skip)
    ctx.autopsy_reason = reason
    log.info(f'Stage 5.1: Autopsy — {reason}')

    if not should_run:
        ctx.autopsy_ran = False
        ctx.stage_status['stage_05_1'] = f'ÜBERSPRUNGEN — {reason}'
        if ctx.coc:
            ctx.coc.add_entry('stage_05_1', f'Autopsy übersprungen: {reason}')
        return ctx

    case_dir = ctx.case_dir / 'raw' / 'autopsy_artefakte' if ctx.case_dir else Path('/tmp/autopsy_case')
    report_dir = case_dir / 'report'
    case_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    try:
        _run_autopsy(ctx.disk_image_path, case_dir, report_dir)
        ctx.autopsy_results = _parse_autopsy_report(report_dir)
        ctx.autopsy_ran     = True
        log.info(f'  Autopsy abgeschlossen: {len(ctx.autopsy_results)} Ergebnisse')
        if ctx.coc:
            ctx.coc.add_entry('stage_05_1', 'Autopsy erfolgreich abgeschlossen')
    except Exception as e:
        log.error(f'  Autopsy Fehler: {e}')
        ctx.autopsy_ran = False
        ctx.stage_errors['stage_05_1'] = str(e)

    return ctx


def should_run_autopsy(ctx: PipelineContext, force: bool = False,
                        skip: bool = False) -> tuple[bool, str]:
    if skip:
        return False, 'Manuell deaktiviert (--no-autopsy)'
    if force:
        return True, 'Manuell erzwungen (--force-autopsy)'
    if ctx.image_count > 100:
        return True, f'Bedingung 5.1.1: {ctx.image_count} Bilddateien gefunden'
    if ctx.email_db_found:
        return True, 'Bedingung 5.1.2: E-Mail-Datenbank gefunden (PST/OST/MBOX)'
    if ctx.encrypted_count > 0:
        return True, f'Bedingung 5.1.3: {ctx.encrypted_count} verschlüsselte Dateien'
    if ctx.unknown_ext_count > 50:
        return True, f'Bedingung 5.1.4: {ctx.unknown_ext_count} unbekannte Dateitypen'
    return False, 'Bedingung 5.1.5: Keine Bedingung erfüllt — Autopsy übersprungen'


def _run_autopsy(image_path: Path, case_dir: Path, report_dir: Path) -> None:
    subprocess.run(
        ['autopsy', '--headless', '--createCase', str(case_dir),
         '--caseName', 'dfir_case', '--caseType', 'single'],
        check=True, timeout=60
    )
    subprocess.run(
        ['autopsy', '--headless', '--addDataSource',
         '--dataSourcePath', str(image_path),
         '--dataSourceType', 'IMAGE', '--caseDir', str(case_dir)],
        check=True, timeout=300
    )
    subprocess.run(
        ['autopsy', '--headless', '--runIngest',
         '--caseDir', str(case_dir)],
        check=True, timeout=3600
    )
    subprocess.run(
        ['autopsy', '--headless', '--generateReport',
         '--reportType', 'XML', '--reportDir', str(report_dir),
         '--caseDir', str(case_dir)],
        check=True, timeout=300
    )


def _parse_autopsy_report(report_dir: Path) -> dict:
    results = {'files': [], 'artifacts': [], 'hash_hits': []}
    report_xml = report_dir / 'report.xml'
    if not report_xml.exists():
        return results
    try:
        tree = ET.parse(report_xml)
        root = tree.getroot()
        for item in root.iter('file'):
            results['files'].append({
                'name':    item.findtext('name', ''),
                'path':    item.findtext('path', ''),
                'md5':     item.findtext('md5', ''),
                'created': item.findtext('created', ''),
            })
        for art in root.iter('artifact'):
            results['artifacts'].append({
                'type':    art.get('type', ''),
                'value':   art.findtext('value', ''),
            })
    except ET.ParseError as e:
        log.warning(f'Autopsy XML Parse-Fehler: {e}')
    return results
