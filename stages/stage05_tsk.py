import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

from tqdm import tqdm
from models.pipeline_context import PipelineContext
from utils.hashing import compute_both

log = logging.getLogger(__name__)

FS_TYPES = ['ntfs', 'fat32', 'exfat', 'ext4', 'ext3', 'ext2']

# TSK 4.15.0 aus Source bevorzugen — erkennt mehr Dateisysteme als GIFT-Version
_TSK_PREFIX = '/usr/local/bin/'
def _tsk(cmd: str) -> str:
    local = Path(f'{_TSK_PREFIX}{cmd}')
    return str(local) if local.exists() else cmd

# Extraktion ist pfadbasiert — setzt fls -r -p voraus (volle Pfade).
# Praefix-Match auf den normalisierten Originalpfad (lowercase, ohne fuehrendes ./).
LOG_PATH_PREFIXES = [
    'var/log/',                        # alle Linux-Logs: syslog, auth, apt/, apache2/,
                                       # nginx/, journal/, audit/, samba/, mail.log, ...
    'var/lib/wtmpdb/',                 # wtmpdb (Y2038-safe wtmp-Nachfolger, SQLite)
    'var/lib/docker/containers/',      # Docker json-Logs
    'var/run/utmp',                    # Live-Sessions (falls im Image vorhanden)
    'run/utmp',
    'windows/system32/winevt/logs/',   # Windows EVTX (NTFS-Partitionen)
    'inetpub/logs/logfiles/',          # IIS u_ex*.log
]
# Dateien ausserhalb der Praefixe — Match auf den Dateinamen (Shell-Histories in Home-Dirs)
LOG_NAME_KEYWORDS = [
    'bash_history', 'zsh_history', 'fish_history',
]


def _analyse_xfs_native(image_path: Path, offset: int) -> List[str]:
    """XFS-Analyse via xfs_db wenn installiert, sonst TSK-Fallback."""
    import shutil
    if not shutil.which('xfs_db'):
        log.warning('  xfs_db nicht gefunden — TSK Fallback für XFS')
        return _analyse_xfs(image_path, offset)
    try:
        result = subprocess.run(
            ['xfs_db', '-r', '-c', 'ls', str(image_path)],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
        entries = [l for l in result.stdout.splitlines() if l.strip()]
        log.info(f'  XFS via xfs_db: {len(entries)} Einträge')
        if not entries:
            log.warning('  xfs_db lieferte keine Einträge — TSK Fallback')
            return _analyse_xfs(image_path, offset)
        return entries
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  xfs_db fehlgeschlagen: {e} — TSK Fallback')
        return _analyse_xfs(image_path, offset)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 5: Disk-Forensik')
    ctx.tsk_fallback_used = True
    ctx.ioc_quality       = 'MITTEL'
    results               = {}
    total_log_extracted   = 0

    # Partitionen aus Stage 02 übernehmen falls vorhanden, sonst neu lesen
    if ctx.partition_layout:
        partitions = [{'start': p['offset'], 'size': int(p['size_mb'] * 1024 * 1024 / 512),
                       'index': p['index']} for p in ctx.partition_layout if p['analysable']]
        log.info(f'  {len(partitions)} analysierbare Partitionen aus Stage 02')
    else:
        partitions = _read_partitions(ctx.disk_image_path)
        log.info(f'  {len(partitions)} Partitionen gefunden (Stage 02 nicht gelaufen)')

    for part in partitions:
        offset  = part['start']
        # Tool aus Stage 02 Tool-Auswahl lesen, sonst Dateisystem erkennen
        tool    = ctx.tool_selection.get(str(offset), '')
        fs_type = _detect_filesystem(ctx.disk_image_path, offset)
        if not tool:
            tool = 'xfs_db' if fs_type == 'xfs' else 'tsk'
        log.info(f'  Partition offset={offset} fs={fs_type} tool={tool}')

        if fs_type in FS_TYPES:
            part_result = _analyse_partition(ctx.disk_image_path, offset, fs_type)
        elif fs_type == 'xfs':
            part_result = _analyse_xfs_native(ctx.disk_image_path, offset)
        else:
            log.warning(f'  Unbekanntes Dateisystem: {fs_type} — übersprungen')
            ctx.tsk_partitions.append({
                'offset': offset, 'fs_type': fs_type, 'status': 'übersprungen', 'files': 0
            })
            continue

        # Gelöschte Dateien aus fls-Output zählen
        deleted = sum(1 for e in part_result if '/-' in e.split('\t')[0] or e.startswith('* '))
        ctx.tsk_deleted_found += deleted

        results[f'partition_{offset}'] = part_result
        ctx.tsk_partitions.append({
            'offset': offset, 'fs_type': fs_type,
            'status': 'analysiert', 'files': len(part_result),
            'deleted': deleted,
        })

        if (fs_type in FS_TYPES or fs_type == 'xfs') and part_result and ctx.case_dir:
            log_dir = ctx.case_dir / 'raw' / 'log_artefakte'
            n, orig_paths, manifest_part = _extract_log_files(
                ctx.disk_image_path, offset, part_result, log_dir, ctx.workers,
                part_index=part.get('index'))
            total_log_extracted += n
            ctx.tsk_extracted_filenames.extend(orig_paths)
            ctx.extraction_manifest.update(manifest_part)
            log.info(f'  {n} Log-Dateien aus Partition {offset} extrahiert → {log_dir}/p{offset}')

    ctx.tsk_results          = results
    ctx.tsk_log_files_extracted = total_log_extracted

    # Extraktions-Manifest persistieren — Grundlage fuer Provenienz (Stage 6/14),
    # Basic Checks (Stage 3.5) und Chain of Custody
    if ctx.case_dir and ctx.extraction_manifest:
        import json
        manifest_path = ctx.case_dir / 'extraction_manifest.json'
        manifest_path.write_text(
            json.dumps(ctx.extraction_manifest, indent=2, ensure_ascii=False),
            encoding='utf-8')
        log.info(f'  Extraktions-Manifest: {len(ctx.extraction_manifest)} Eintraege → {manifest_path}')

    out_dir = ctx.case_dir / 'raw' / 'disk_artefakte' if ctx.case_dir else Path('/tmp/tsk_out')
    out_dir.mkdir(parents=True, exist_ok=True)

    # Wiederherstellung gelöschter Dateien — PRO PARTITION mit Offset.
    # Früher: tsk_recover <image> <out> (kein Offset) → scannte das komplette
    # Image und alle Partitionen gleichzeitig → OOM-Killer SIGKILL auf großen Images.
    # Fix: -o <offset> pro analysierter Partition → isoliert + RAM-sicher.
    for part_info in ctx.tsk_partitions:
        if part_info.get('status') != 'analysiert':
            continue
        part_out = out_dir / f'partition_{part_info["offset"]}'
        part_out.mkdir(parents=True, exist_ok=True)
        _recover_deleted(ctx.disk_image_path, part_out, offset=part_info['offset'])

    # Wiederhergestellte Dateien zählen
    recovered_files = [f for f in out_dir.rglob('*') if f.is_file()]
    ctx.tsk_deleted_recovered     = len(recovered_files)
    ctx.tsk_deleted_not_recovered = max(0, ctx.tsk_deleted_found - ctx.tsk_deleted_recovered)

    # MACtime wird NACH Stage 6 aufgerufen (via run_mactime_after_stage6)
    # damit events.db bereits existiert und nicht überschrieben wird

    # Alle extrahierten Dateien hashen und in Chain of Custody eintragen
    if ctx.coc and ctx.case_dir:
        _hash_extracted_files(ctx.case_dir / 'raw' / 'log_artefakte', ctx)
        _hash_extracted_files(out_dir, ctx)

    log.info(f'  TSK: {sum(len(v) for v in results.values())} Einträge')
    log.info(f'  Gelöscht gefunden: {ctx.tsk_deleted_found} | '
             f'Wiederhergestellt: {ctx.tsk_deleted_recovered} | '
             f'Nicht wiederherstellbar: {ctx.tsk_deleted_not_recovered}')
    if ctx.coc:
        ctx.coc.add_entry('stage_05',
            f'TSK: {len(results)} Partitionen | '
            f'{total_log_extracted} Log-Dateien | '
            f'{ctx.tsk_deleted_recovered} gelöschte Dateien wiederhergestellt | '
            f'{len(ctx.coc.extracted_file_hashes)} Dateien gehasht')
    return ctx


def run_mactime_after_stage6(ctx: PipelineContext) -> PipelineContext:
    """Wird nach Stage 6 aufgerufen — events.db existiert dann bereits."""
    if ctx.skip_mactime or not ctx.disk_image_path or not ctx.events_db_path:
        return ctx
    for part in ctx.tsk_partitions:
        if part['status'] == 'analysiert':
            _generate_mactime_streaming(
                ctx.disk_image_path, part['offset'], ctx.events_db_path, ctx)
            _run_sorter(ctx.disk_image_path, part['offset'],
                        ctx.case_dir / 'raw' / 'sorter_output', ctx)
    return ctx


def _hash_extracted_files(directory: Path, ctx) -> None:
    if not directory.is_dir():
        return
    for f in directory.rglob('*'):
        if not f.is_file():
            continue
        try:
            sha256, _ = compute_both(f)
            ctx.coc.add_file_hash(f.name, sha256)
        except Exception:
            pass


def _read_partitions(image_path: Path) -> List[dict]:
    partitions = []
    try:
        result = subprocess.run(
            [_tsk('mmls'), str(image_path)],
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
            [_tsk('fsstat'), '-o', str(offset), str(image_path)],
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
            [_tsk('fls'), '-r', '-p', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
        entries = [l for l in result.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'fls fehlgeschlagen: {e}')
    return entries


def _icat_extract(args: Tuple) -> bool:
    image_path, offset, inode, out_file = args
    try:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [_tsk('icat'), '-o', str(offset), str(image_path), inode],
            capture_output=True, timeout=30
        )
        if result.stdout:
            out_file.write_bytes(result.stdout)
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def _extract_log_files(image_path: Path, offset: int, fls_entries: List[str],
                       log_dir: Path, workers: int = 2,
                       part_index=None) -> Tuple[int, List[str], dict]:
    """Extrahiert log-relevante Dateien einer Partition via icat.

    Zielstruktur: log_dir/p<offset>/<originalpfad>
    — kollisionsfrei ueber mehrere Partitionen, Originalpfad bleibt erhalten.

    Rueckgabe: (anzahl_erfolgreich, originalpfade_erfolgreich, manifest)
    manifest = {extrahierter_pfad: {orig_path, partition_offset,
                partition_index, inode, deleted, success, method}}
    """
    work_items: List[Tuple] = []
    used_out:   set = set()

    for entry in fls_entries:
        parts = entry.split('\t')
        if len(parts) < 2:
            continue
        meta   = parts[0].strip()
        fpath  = parts[1].strip()
        # Nur regulaere Dateien extrahieren — Verzeichnisse (d/d) ueberspringen
        if meta.startswith('d/'):
            continue
        # Pfad normalisieren: fuehrendes './' weg, lowercase nur fuers Matching
        rel = fpath.removeprefix('./').lstrip('/')
        rel_norm = rel.lower()
        if not (any(rel_norm.startswith(pre) for pre in LOG_PATH_PREFIXES)
                or any(kw in Path(rel_norm).name for kw in LOG_NAME_KEYWORDS)):
            continue
        tokens = meta.split()
        if len(tokens) < 2:
            continue
        inode = tokens[-1].rstrip(':').split('-')[0]
        if not inode.isdigit():
            continue
        is_deleted = ' * ' in f' {meta} '   # fls markiert geloeschte Eintraege mit *

        rel_safe = rel.replace(':', '_')    # NTFS-ADS / Sonderzeichen
        out_file = log_dir / f'p{offset}' / rel_safe
        if str(out_file) in used_out:
            # gleicher Pfad doppelt im fls-Output (z.B. allozierte + geloeschte
            # Version) — Inode anhaengen statt ueberschreiben
            out_file = out_file.with_name(f'{out_file.name}.inode{inode}')
        used_out.add(str(out_file))
        work_items.append((image_path, offset, inode, out_file,
                           '/' + rel, is_deleted))

    log.info(f'  {len(work_items):,} Log-relevante Eintraege — starte Extraktion mit {workers} Threads...')

    extracted  = 0
    orig_paths: List[str] = []
    manifest:   dict      = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_icat_extract, item[:4]): item
            for item in work_items
        }
        progress = tqdm(
            as_completed(futures),
            total=len(work_items),
            desc=f'  Extraktion offset={offset}',
            unit='Datei',
            dynamic_ncols=True,
        )
        for future in progress:
            _img, _off, inode, out_file, orig_path, is_deleted = futures[future]
            try:
                ok = bool(future.result())
            except Exception:
                ok = False
            if ok:
                extracted += 1
                orig_paths.append(orig_path)
                progress.set_postfix({'extrahiert': extracted})
            manifest[str(out_file)] = {
                'orig_path':        orig_path,
                'partition_offset': offset,
                'partition_index':  part_index,
                'inode':            inode,
                'deleted':          is_deleted,
                'success':          ok,
                'method':           'tsk_icat',
            }

    return extracted, orig_paths, manifest


def _analyse_xfs(image_path: Path, offset: int) -> List[str]:
    # fls unterstützt XFS — gleicher Output wie _analyse_partition, daher icat-kompatibel
    try:
        result = subprocess.run(
            [_tsk('fls'), '-r', '-p', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
        entries = [l for l in result.stdout.splitlines() if l.strip()]
        log.info(f'  XFS via fls: {len(entries)} Einträge')
        return entries
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  fls für XFS fehlgeschlagen: {e}')
    return []


def _generate_mactime_streaming(image_path: Path, offset: int,
                                db_path: Path, ctx) -> None:
    """Streamt MACtime via mactime-Tool direkt in DuckDB — kein RAM-Problem."""
    import re
    from datetime import datetime, timezone
    from models.event import ForensicEvent
    from utils.event_store import EventStore

    # mactime Space-Format: date   size macb mode uid gid inode   filename
    RE = re.compile(
        r'^(?P<date>\w{3} \w{3}\s+\d+ \d{4} \d{2}:\d{2}:\d{2})\s+'
        r'(?P<size>\d+)\s+'
        r'(?P<macb>[macb\.]+)\s+'
        r'(?P<mode>\S+)\s+'
        r'(?P<uid>\d+)\s+'
        r'(?P<gid>\d+)\s+'
        r'(?P<inode>\S+)\s+'
        r'(?P<filename>.+)$'
    )

    try:
        # Schritt 1: fls -m generiert Body-File
        fls = subprocess.run(
            [_tsk('fls'), '-m', '/', '-r', '-o', str(offset), str(image_path)],
            capture_output=True, timeout=600, errors='replace', text=True,
        )
        if not fls.stdout:
            log.warning('  MACtime: fls -m lieferte kein Output')
            return

        # Schritt 2: mactime konvertiert Body-File → Timeline
        mt = subprocess.run(
            [_tsk('mactime'), '-b', '-'],
            input=fls.stdout,
            capture_output=True, text=True, timeout=300,
            errors='replace',
        )
        if not mt.stdout:
            log.warning('  MACtime: mactime lieferte kein Output')
            return

        # Schritt 3: Zeile für Zeile in DuckDB streamen
        db_path.parent.mkdir(parents=True, exist_ok=True)
        batch = []
        count = 0

        with EventStore(db_path) as store:
            for line in mt.stdout.splitlines():
                if not line or line.startswith('#'):
                    continue
                m = RE.match(line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(
                        m.group('date').strip(), '%a %b %d %Y %H:%M:%S'
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

                filename = m.group('filename').strip()
                macb     = m.group('macb')
                size     = m.group('size')

                severity = 'info'
                if any(s in filename for s in ['/tmp/', '/var/tmp/', '/dev/shm']):
                    severity = 'medium'
                if filename.startswith('* '):
                    severity = 'high'

                batch.append(ForensicEvent(
                    timestamp  = ts,
                    source     = 'mactime',
                    event_type = f'filesystem_{macb.replace(".", "").strip() or "access"}',
                    message    = f'[{macb}] {filename} ({size} bytes)',
                    file_path  = filename,
                    severity   = severity,
                ))
                count += 1

                if len(batch) >= 1000:
                    store.insert_events(batch)
                    batch.clear()

            if batch:
                store.insert_events(batch)

        ctx.tsk_mactime_events = count
        log.info(f'  MACtime Streaming: {count:,} Events direkt in DuckDB')

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  MACtime Streaming fehlgeschlagen: {e}')


def _generate_mactime(image_path: Path, offset: int,
                      log_dir: Path, ctx) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    body_file    = log_dir / f'mactime_body_{offset}.txt'
    mactime_file = log_dir / 'mactime_timeline.txt'
    try:
        # fls -m erzeugt Body-File mit allen Timestamps
        result = subprocess.run(
            [_tsk('fls'), '-m', '/', '-r', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=600, errors='replace'
        )
        if result.stdout:
            body_file.write_text(result.stdout, encoding='utf-8', errors='replace')
            # mactime konvertiert Body-File → lesbare Timeline
            mt_result = subprocess.run(
                ['mactime', '-b', str(body_file)],
                capture_output=True, text=True, timeout=120
            )
            if mt_result.stdout:
                mactime_file.write_text(mt_result.stdout,
                                        encoding='utf-8', errors='replace')
                lines = [l for l in mt_result.stdout.splitlines() if l.strip()]
                ctx.tsk_mactime_events = len(lines)
                ctx.tsk_mactime_file   = str(mactime_file)
                log.info(f'  MACtime: {ctx.tsk_mactime_events} Einträge → {mactime_file}')
            body_file.unlink(missing_ok=True)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  MACtime fehlgeschlagen: {e}')


def _run_sorter(image_path: Path, offset: int,
                out_dir: Path, ctx) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [_tsk('sorter'), '-o', str(offset), '-d', str(out_dir), str(image_path)],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
        categories: Dict[str, int] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if ':' in line:
                parts = line.split(':')
                if len(parts) == 2:
                    try:
                        categories[parts[0].strip()] = int(parts[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
        ctx.tsk_sorter_ran        = True
        ctx.tsk_sorter_categories = categories

        # Sorter-Output: TSK sorter schreibt Textdateien pro Kategorie
        # (exec.txt, documents.txt, images.txt, ...) — KEINE Unterordner
        # Jede Datei enthält einen Dateipfad pro Zeile (ggf. tab-getrennt).
        _CAT_FILES = {
            'exec.txt':      'exec',
            'documents.txt': 'documents',
            'images.txt':    'images',
            'text.txt':      'text',
            'archive.txt':   'archive',
            'compress.txt':  'archive',
            'audio.txt':     'audio',
            'video.txt':     'video',
            'crypto.txt':    'crypto',
            'data.txt':      'data',
            'disk.txt':      'disk',
            'system.txt':    'system',
            'unknown.txt':   'unknown',
        }
        sorter_files: Dict[str, str] = {}
        for cat_filename, category in _CAT_FILES.items():
            cat_path = out_dir / cat_filename
            if not cat_path.exists() or cat_path.stat().st_size == 0:
                continue
            for line in cat_path.read_text(errors='replace').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Zeilen können sein: "/pfad/datei" oder "inode\t/pfad/datei"
                parts = line.split('\t')
                fpath = parts[-1].strip()
                fname = Path(fpath).name
                if fname:
                    sorter_files[fname] = category

        ctx.tsk_sorter_files = sorter_files
        log.info(f'  Sorter: {len(categories)} Kategorien, {len(sorter_files)} Dateien klassifiziert')
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  Sorter fehlgeschlagen: {e}')


def _recover_deleted(image_path: Path, out_dir: Path, offset: int = 0) -> None:
    """Stellt gelöschte Dateien via tsk_recover wieder her.
    offset MUSS gesetzt sein — ohne Offset scannt tsk_recover das gesamte Image
    aller Partitionen gleichzeitig und triggert den OOM-Killer auf großen Images."""
    cmd = [_tsk('tsk_recover')]
    if offset:
        cmd += ['-o', str(offset)]
    cmd += [str(image_path), str(out_dir)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=600)
        log.info(f'  Gelöschte Dateien wiederhergestellt (offset={offset}) → {out_dir}')
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'tsk_recover fehlgeschlagen (offset={offset}): {e}')
