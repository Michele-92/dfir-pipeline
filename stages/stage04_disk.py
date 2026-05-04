import subprocess
import json
import logging
from pathlib import Path

from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

DISSECT_FUNCTIONS = [
    'mft', 'registry', 'prefetch', 'lnk', 'shellbags',
    'jumplist', 'browser', 'ssh', 'bash', 'crontab', 'users', 'network',
]

IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.raw'}
EMAIL_EXTENSIONS = {'.pst', '.ost', '.mbox', '.eml', '.msg'}
ENCRYPTED_MAGIC  = [b'ENCRYPTED', b'\x7fELF\x02', b'PK\x03\x04']


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 4: Dissect')
    artifacts = {}
    out_dir = ctx.case_dir / 'raw' / 'disk_artefakte' if ctx.case_dir else Path('/tmp/dfir_disk')
    out_dir.mkdir(parents=True, exist_ok=True)

    for func in DISSECT_FUNCTIONS:
        try:
            result = subprocess.run(
                ['target-query', '-t', str(ctx.disk_image_path), func],
                capture_output=True, text=True, timeout=300
            )
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            artifacts[func] = lines
            log.info(f'  Dissect {func}: {len(lines)} Einträge')
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning(f'  Dissect {func} fehlgeschlagen: {e}')
            artifacts[func] = []

    ctx.disk_artifacts = artifacts

    total = sum(len(v) for v in artifacts.values())
    ctx.dissect_empty  = total == 0

    ctx.image_count       = _count_images(artifacts)
    ctx.email_db_found    = _check_email_db(artifacts)
    ctx.encrypted_count   = _count_encrypted(artifacts)
    ctx.unknown_ext_count = _count_unknown(artifacts)

    log.info(f'  Bilder: {ctx.image_count}, E-Mail-DB: {ctx.email_db_found}, '
             f'Verschlüsselt: {ctx.encrypted_count}, Unbekannt: {ctx.unknown_ext_count}')
    if ctx.dissect_empty:
        log.warning('  Dissect leer — TSK Fallback wird aktiviert')

    if ctx.coc:
        ctx.coc.add_entry('stage_05', f'Dissect: {total} Artefakte')
    return ctx


def _count_images(artifacts: dict) -> int:
    count = 0
    for lines in artifacts.values():
        for line in lines:
            if any(line.lower().endswith(ext) for ext in IMAGE_EXTENSIONS):
                count += 1
    return count


def _check_email_db(artifacts: dict) -> bool:
    for lines in artifacts.values():
        for line in lines:
            if any(line.lower().endswith(ext) for ext in EMAIL_EXTENSIONS):
                return True
    return False


def _count_encrypted(artifacts: dict) -> int:
    count = 0
    for lines in artifacts.values():
        for line in lines:
            if any(kw in line.lower() for kw in ['encrypted', 'bitlocker', 'luks', 'veracrypt']):
                count += 1
    return count


def _count_unknown(artifacts: dict) -> int:
    known_ext = {'.txt', '.log', '.cfg', '.conf', '.xml', '.json', '.csv',
                 '.exe', '.dll', '.sys', '.bat', '.ps1', '.sh', '.py'}
    count = 0
    for lines in artifacts.values():
        for line in lines:
            p = Path(line.strip())
            if p.suffix and p.suffix.lower() not in known_ext:
                count += 1
    return count
