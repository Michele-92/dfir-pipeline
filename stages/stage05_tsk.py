import hashlib
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Tuple

from tqdm import tqdm
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

FS_TYPES = ['ntfs', 'fat32', 'exfat', 'ext4', 'ext3', 'ext2']

LOG_KEYWORDS = [
    'var/log', 'bash_history', 'zsh_history', 'fish_history',
    'auth.log', 'syslog', 'kern.log', 'messages', 'secure',
    'apache', 'nginx', 'mysql', 'postgresql', 'audit', 'fail2ban',
    'wtmp', 'btmp', 'lastlog', 'utmp', 'dpkg.log', 'apt', 'cron',
    'openvpn', 'samba', 'postfix', 'vsftpd', 'docker',
]


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 5: TSK Fallback aktiv')
    ctx.tsk_fallback_used = True
    ctx.ioc_quality       = 'MITTEL'
    results               = {}

    partitions = _read_partitions(ctx.disk_image_path)
    log.info(f'  {len(partitions)} Partitionen gefunden')

    for part in partitions:
        offset  = part['start']
        fs_type = _detect_filesystem(ctx.disk_image_path, offset)
        log.info(f'  Partition offset={offset} fs={fs_type}')

        if fs_type in FS_TYPES:
            part_result = _analyse_partition(ctx.disk_image_path, offset, fs_type)
        elif fs_type == 'xfs':
            part_result = _analyse_xfs(ctx.disk_image_path, offset)
        else:
            log.warning(f'  Unbekanntes Dateisystem: {fs_type} — übersprungen')
            continue

        results[f'partition_{offset}'] = part_result

        if (fs_type in FS_TYPES or fs_type == 'xfs') and part_result and ctx.case_dir:
            log_dir = ctx.case_dir / 'raw' / 'log_artefakte'
            n = _extract_log_files(ctx.disk_image_path, offset, part_result, log_dir, ctx.workers)
            log.info(f'  {n} Log-Dateien aus Partition {offset} extrahiert → {log_dir}')

    ctx.tsk_results = results

    out_dir = ctx.case_dir / 'raw' / 'disk_artefakte' if ctx.case_dir else Path('/tmp/tsk_out')
    out_dir.mkdir(parents=True, exist_ok=True)
    _recover_deleted(ctx.disk_image_path, out_dir)

    # Alle extrahierten Dateien hashen und in Chain of Custody eintragen
    if ctx.coc and ctx.case_dir:
        _hash_extracted_files(ctx.case_dir / 'raw' / 'log_artefakte', ctx)
        _hash_extracted_files(out_dir, ctx)

    log.info(f'  TSK: {sum(len(v) for v in results.values())} Einträge')
    if ctx.coc:
        ctx.coc.add_entry('stage_05',
            f'TSK Fallback: {len(results)} Partitionen | '
            f'{len(ctx.coc.extracted_file_hashes)} Dateien gehasht')
    return ctx


def _hash_extracted_files(directory: Path, ctx) -> None:
    if not directory.is_dir():
        return
    for f in directory.rglob('*'):
        if not f.is_file():
            continue
        try:
            sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
            ctx.coc.add_file_hash(f.name, sha256)
        except Exception:
            pass


def _read_partitions(image_path: Path) -> List[dict]:
    partitions = []
    try:
        result = subprocess.run(
            ['mmls', str(image_path)],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].rstrip(':').isdigit():
                try:
                    partitions.append({
                        'index': int(parts[0].rstrip(':')),
                        'start': int(parts[2]),
                        'size':  int(parts[3]) if len(parts) > 3 else 0,
                    })
                except ValueError:
                    continue
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'mmls fehlgeschlagen: {e}')
    return partitions


def _detect_filesystem(image_path: Path, offset: int) -> str:
    try:
        result = subprocess.run(
            ['fsstat', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=30, errors='replace'
        )
        output = result.stdout.lower()
        for fs in ['ntfs', 'fat32', 'exfat', 'ext4', 'ext3', 'ext2', 'xfs', 'btrfs']:
            if fs in output:
                return fs
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return 'unknown'


def _analyse_partition(image_path: Path, offset: int, fs_type: str) -> List[str]:
    entries = []
    try:
        result = subprocess.run(
            ['fls', '-r', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
        entries = [l for l in result.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'fls fehlgeschlagen: {e}')
    return entries


def _icat_extract(args: Tuple) -> bool:
    image_path, offset, inode, out_file = args
    try:
        result = subprocess.run(
            ['icat', '-o', str(offset), str(image_path), inode],
            capture_output=True, timeout=30
        )
        if result.stdout:
            out_file.write_bytes(result.stdout)
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def _extract_log_files(image_path: Path, offset: int, fls_entries: List[str],
                       log_dir: Path, workers: int = 2) -> int:
    log_dir.mkdir(parents=True, exist_ok=True)

    # Phase 1: Relevante Einträge filtern und Dateinamen vorab eindeutig vergeben
    work_items: List[Tuple] = []
    used_names: set = set()
    for entry in fls_entries:
        if not any(kw in entry.lower() for kw in LOG_KEYWORDS):
            continue
        parts = entry.split('\t')
        if len(parts) < 2:
            continue
        meta   = parts[0].strip()
        fpath  = parts[1].strip()
        tokens = meta.split()
        if len(tokens) < 2:
            continue
        inode = tokens[-1].rstrip(':').split('-')[0]
        if not inode.isdigit():
            continue
        out_name = Path(fpath).name.replace(':', '_')
        if out_name in used_names:
            out_name = f'{inode}_{out_name}'
        used_names.add(out_name)
        work_items.append((image_path, offset, inode, log_dir / out_name))

    log.info(f'  {len(work_items):,} Log-relevante Einträge gefunden — starte Extraktion mit {workers} Threads...')

    # Phase 2: Parallel extrahieren mit ThreadPoolExecutor
    extracted = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_icat_extract, item): item for item in work_items}
        progress = tqdm(
            as_completed(futures),
            total=len(work_items),
            desc=f'  Extraktion offset={offset}',
            unit='Datei',
            dynamic_ncols=True,
        )
        for future in progress:
            try:
                if future.result():
                    extracted += 1
                    progress.set_postfix({'extrahiert': extracted})
            except Exception:
                pass

    return extracted


def _analyse_xfs(image_path: Path, offset: int) -> List[str]:
    # fls unterstützt XFS — gleicher Output wie _analyse_partition, daher icat-kompatibel
    try:
        result = subprocess.run(
            ['fls', '-r', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
        entries = [l for l in result.stdout.splitlines() if l.strip()]
        log.info(f'  XFS via fls: {len(entries)} Einträge')
        return entries
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  fls für XFS fehlgeschlagen: {e}')
    return []


def _recover_deleted(image_path: Path, out_dir: Path) -> None:
    try:
        subprocess.run(
            ['tsk_recover', str(image_path), str(out_dir)],
            capture_output=True, timeout=600
        )
        log.info(f'  Gelöschte Dateien wiederhergestellt → {out_dir}')
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'tsk_recover fehlgeschlagen: {e}')
