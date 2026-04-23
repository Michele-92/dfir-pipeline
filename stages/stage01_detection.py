import logging
from datetime import datetime
from pathlib import Path

from models.pipeline_context import PipelineContext
from models.chain_of_custody import ChainOfCustody
from utils.hashing import compute_both
from utils.file_detection import detect_format, detect_format_by_extension

log = logging.getLogger(__name__)

MONATE = ['','Januar','Februar','März','April','Mai','Juni',
          'Juli','August','September','Oktober','November','Dezember']
TAGE   = ['Montag','Dienstag','Mittwoch','Donnerstag','Freitag','Samstag','Sonntag']


def run(ctx: PipelineContext) -> PipelineContext:
    path = ctx.disk_image_path
    log.info(f'Stage 1: Analysiere {path}')

    # Dateityp erkennen
    try:
        import magic
        raw_magic    = magic.from_file(str(path))
        ctx.file_type = detect_format(raw_magic)
    except (ImportError, Exception):
        ctx.file_type = detect_format_by_extension(path)

    # Dateigröße
    ctx.file_size_gb = path.stat().st_size / (1024 ** 3)
    log.info(f'Format: {ctx.file_type}, Größe: {ctx.file_size_gb:.2f} GB')

    # Hashes berechnen
    log.info('Berechne SHA256 + MD5...')
    ctx.sha256, ctx.md5 = compute_both(path)
    log.info(f'SHA256: {ctx.sha256[:16]}...')

    # Ausgabe-Ordnerstruktur
    ctx.case_dir = _create_case_dir(ctx.output_dir)
    log.info(f'Case-Verzeichnis: {ctx.case_dir}')

    # Chain of Custody starten
    ctx.coc = ChainOfCustody(
        file_name  = path.name,
        sha256     = ctx.sha256,
        md5        = ctx.md5,
        size_gb    = ctx.file_size_gb,
        start_time = datetime.utcnow(),
    )
    ctx.coc.add_entry('stage_01', 'Dateierkennung abgeschlossen')
    return ctx


def _create_case_dir(output_dir: Path) -> Path:
    now   = datetime.now()
    monat = f'{now.month:02d}_{MONATE[now.month]}'
    tag   = f'{now.day:02d}_{TAGE[now.weekday()]}'
    case  = f'case_{now.strftime("%Y%m%d_%H%M%S")}'
    case_dir = output_dir / str(now.year) / monat / tag / case
    for sub in ['raw/disk_artefakte', 'raw/memory_artefakte',
                'raw/log_artefakte', 'raw/autopsy_artefakte']:
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    return case_dir
