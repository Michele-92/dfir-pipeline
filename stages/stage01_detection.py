import logging
from datetime import datetime
from pathlib import Path

from models.pipeline_context import PipelineContext
from models.chain_of_custody import ChainOfCustody
from utils.hashing import compute_both
from utils.file_detection import detect_format, detect_format_by_extension
from utils.e01_reader import read_e01_hashes, read_e01_media_size

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

    # Dateigröße — bei E01 beide Größen speichern:
    #   file_size_gb           = logische Disk-Größe (unkomprimiert, via img_stat)
    #   file_size_compressed_gb = physische Dateigröße der E01-Datei auf Disk
    if ctx.file_type in ('E01', 'EWF'):
        ctx.file_size_compressed_gb = path.stat().st_size / (1024 ** 3)
        logical_bytes = read_e01_media_size(path)
        ctx.file_size_gb = (logical_bytes / (1024 ** 3)
                            if logical_bytes
                            else ctx.file_size_compressed_gb)
    else:
        ctx.file_size_gb = path.stat().st_size / (1024 ** 3)
        ctx.file_size_compressed_gb = 0.0
    log.info(f'Format: {ctx.file_type}, Größe: {ctx.file_size_gb:.2f} GB')

    # Hashes — bei E01 eingebettete Hashes auslesen, sonst berechnen
    if ctx.file_type in ('E01', 'EWF'):
        md5, sha1 = read_e01_hashes(path)
        if md5:
            ctx.md5        = md5
            ctx.sha256     = sha1
            ctx.hash_source = 'E01-eingebettet'
            log.info(f'E01-Hash gelesen: MD5={md5[:16]}...')
        else:
            log.info('E01-Hash nicht lesbar — berechne neu...')
            ctx.sha256, ctx.md5 = compute_both(path)
            ctx.hash_source = 'Berechnet'
    else:
        log.info('Berechne SHA256 + MD5...')
        ctx.sha256, ctx.md5 = compute_both(path)
        ctx.hash_source = 'Berechnet'
    log.info(f'Hash-Quelle: {ctx.hash_source}')

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
    for sub in ['raw/disk_artefakte', 'raw/log_artefakte']:
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    return case_dir
