import csv
import io
import logging
import subprocess
import yaml
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from tqdm import tqdm
from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from utils.event_store import EventStore
from stages.stage05_tsk import LOG_PATH_PREFIXES, LOG_NAME_KEYWORDS
from parsers import (
    JournaldParser, WtmpParser, WtmpdbParser, UtmpParser, LastlogParser,
    AuthLogParser, CronParser, AuditParser, Fail2BanParser,
    UFWParser, KernLogParser, BootLogParser, DaemonLogParser, SyslogParser,
    DpkgParser, AptHistoryParser, YumParser, DnfParser, PacmanParser,
    ApacheAccessParser, ApacheErrorParser, NginxAccessParser, NginxErrorParser,
    MySQLErrorParser, PostgreSQLParser, MongoDBParser,
    BashHistoryParser, ZshHistoryParser, FishHistoryParser,
    PostfixMailParser, FTPParser, SambaParser, OpenVPNParser,
    DockerParser, ContainerdParser, IISLogParser, PlasaFallbackParser,
)

log = logging.getLogger(__name__)

# Reihenfolge = Routing-Prioritaet (first match wins).
# WtmpdbParser VOR WtmpParser (wtmp.db beginnt mit 'wtmp').
# Entfernt (Review-Fix #21): SSHParser (Duplikat von AuthLogParser, kam nie
# zum Zug), EVTXParser (EVTX laeuft zentral ueber Hayabusa in Stage 4.3 —
# vorher wurden dieselben Dateien doppelt verarbeitet).
ALL_PARSERS = [
    JournaldParser(),
    WtmpdbParser(),
    WtmpParser(),
    UtmpParser(),
    LastlogParser(),
    AuthLogParser(),
    CronParser(),
    AuditParser(),
    Fail2BanParser(),
    UFWParser(),
    KernLogParser(),
    BootLogParser(),
    DaemonLogParser(),
    SyslogParser(),
    DpkgParser(),
    AptHistoryParser(),
    YumParser(),
    DnfParser(),
    PacmanParser(),
    ApacheAccessParser(),
    ApacheErrorParser(),
    NginxAccessParser(),
    NginxErrorParser(),
    MySQLErrorParser(),
    PostgreSQLParser(),
    MongoDBParser(),
    BashHistoryParser(),
    ZshHistoryParser(),
    FishHistoryParser(),
    PostfixMailParser(),
    FTPParser(),
    SambaParser(),
    OpenVPNParser(),
    DockerParser(),
    ContainerdParser(),
    IISLogParser(),
    PlasaFallbackParser(),
]

_BATCH_SIZE = 1000


def run(ctx: PipelineContext) -> PipelineContext:
    workers = ctx.workers
    log.info(f'Stage 6: Log-Parsing ({workers} Worker)')
    log_files = _find_log_files(ctx)
    log.info(f'  {len(log_files)} Log-Dateien gefunden')
    log.info(f'  Parsing mit {workers} parallelen Worker-Prozessen — schreibe Events in DuckDB...')

    db_path = ctx.output_dir / 'events.db'
    if db_path.exists():
        db_path.unlink()

    total_lines   = 0
    parsed_count  = 0
    parser_stats: dict = {}
    parser_file_map: dict = {}
    batch: List[ForensicEvent] = []

    with EventStore(db_path) as store:
        manifest = ctx.extraction_manifest or {}

        def _prov_for(lf: Path) -> dict:
            """Provenienz einer extrahierten Datei: Originalpfad auf dem
            Image, Partition, Extraktionsmethode (Review-Punkt #7)."""
            entry = manifest.get(str(lf))
            if entry and entry.get('orig_path'):
                off  = entry.get('partition_offset', '?')
                idx  = entry.get('partition_index')
                part = (f'Partition {idx} (offset {off})'
                        if idx is not None else f'offset {off}')
                return {'orig_path':  entry['orig_path'],
                        'partition':  part,
                        'extraction': entry.get('method', 'tsk_icat')}
            if ctx.case_dir:
                # log_artefakte/p<offset>/<pfad>  bzw.
                # disk_artefakte/partition_<offset>/<pfad> (tsk_recover)
                for sub, method in (('raw/log_artefakte',  'tsk_icat'),
                                    ('raw/disk_artefakte', 'tsk_recover')):
                    base = ctx.case_dir / sub
                    try:
                        rel = lf.relative_to(base).as_posix()
                    except ValueError:
                        continue
                    first, _, rest = rel.partition('/')
                    if rest and (first.startswith('p') or first.startswith('partition_')):
                        off = first.removeprefix('partition_').removeprefix('p')
                        return {'orig_path': '/' + rest,
                                'partition': f'offset {off}',
                                'extraction': method}
                    return {'orig_path': '/' + rel, 'partition': '',
                            'extraction': method}
            return {'orig_path': '', 'partition': '', 'extraction': 'logs_dir'}

        system_tz = ctx.timezone or 'UTC'
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(route_and_parse, lf, _prov_for(lf),
                                       system_tz): lf
                       for lf in log_files}
            progress = tqdm(
                as_completed(futures),
                total=len(log_files),
                unit='Datei',
                desc='  Stage 6',
                dynamic_ncols=True,
            )
            for future in progress:
                lf = futures[future]
                try:
                    parser_name, events = future.result()
                except Exception as e:
                    log.warning(f'Parser fehlgeschlagen für {lf.name}: {e}')
                    parser_name, events = 'fehler', []
                # parser_file_map erfasst JEDE geroutete Datei — auch mit
                # 0 Events (Review-Fix: Dateien ohne Treffer waren unsichtbar)
                file_label = _prov_for(lf).get('orig_path') or str(lf)
                if parser_name not in parser_file_map:
                    parser_file_map[parser_name] = {'count': 0, 'files': []}
                parser_file_map[parser_name]['count'] += len(events)
                parser_file_map[parser_name]['files'].append(file_label)
                if events:
                    batch.extend(events)
                    parsed_count += len(events)
                    for e in events:
                        parser_stats[e.source] = parser_stats.get(e.source, 0) + 1
                    if len(batch) >= _BATCH_SIZE:
                        store.insert_events(batch)
                        batch.clear()
                try:
                    total_lines += sum(1 for _ in lf.open('rb'))
                except Exception:
                    pass
                progress.set_postfix({'Events': f'{parsed_count:,}'})
        if batch:
            store.insert_events(batch)

    ctx.events_db_path   = db_path
    ctx.parser_stats     = parser_stats
    ctx.parser_file_map  = parser_file_map
    ctx.all_parser_names = [p.name for p in ALL_PARSERS]
    ctx.total_log_lines  = total_lines
    ctx.parsed_events    = parsed_count
    ctx.events           = []  # Daten leben in events.db

    log.info(f'  {ctx.parsed_events} Events aus {total_lines} Log-Zeilen geparst')

    # ── Stage 4.3: Hayabusa EVTX-Analyse ─────────────────────────────────────
    evtx_files = _find_evtx_files(ctx)
    if evtx_files:
        log.info(f'Stage 4.3: Hayabusa — {len(evtx_files)} EVTX-Datei(en) gefunden')
        hayabusa_events = _run_hayabusa(evtx_files)
        if hayabusa_events:
            with EventStore(db_path) as store:
                store.insert_events(hayabusa_events)
            ctx.parsed_events        += len(hayabusa_events)
            ctx.hayabusa_hits         = len(hayabusa_events)
            parser_stats['hayabusa']  = len(hayabusa_events)
            ctx.stage_status['stage_04_3'] = f'AKTIV — {len(hayabusa_events)} Sigma-Treffer aus {len(evtx_files)} EVTX-Datei(en)'
            log.info(f'  Hayabusa: {len(hayabusa_events)} Sigma-Treffer eingefügt')
            if ctx.coc:
                ctx.coc.add_entry('stage_04_3', f'Hayabusa: {len(hayabusa_events)} Treffer')
        else:
            ctx.stage_status['stage_04_3'] = f'ÜBERSPRUNGEN — {len(evtx_files)} EVTX-Datei(en) gefunden, aber Hayabusa Binary nicht verfügbar oder keine Treffer'
            log.info('  Hayabusa: keine Treffer oder Binary nicht gefunden')
    else:
        ctx.stage_status['stage_04_3'] = 'ÜBERSPRUNGEN — keine EVTX-Dateien im Input gefunden'
        log.info('Stage 4.3: Hayabusa — keine EVTX-Dateien, übersprungen')

    if ctx.coc:
        ctx.coc.add_entry('stage_06', f'Log-Parsing: {ctx.parsed_events} Events')
    return ctx


def route_and_parse(log_file: Path, prov: dict = None,
                    system_tz: str = 'UTC'):
    """Routet eine Datei zum passenden Parser und stempelt Provenienz.

    can_parse() prueft den ORIGINALPFAD auf dem Image (aus dem Manifest) —
    pfadbasierte Checks wie 'apache' in str(path) funktionieren damit.
    Geparst wird die extrahierte Datei. Jedes Event erhaelt: orig_path,
    source_file, partition, parser_name, extraction (Review-Punkt #7).

    Rueckgabe: (parser_name, events)
    """
    prov = prov or {}
    orig_path  = prov.get('orig_path', '')
    route_path = Path(orig_path) if orig_path else log_file

    chosen = None
    for parser in ALL_PARSERS:
        if parser.name == 'text_fallback':
            continue
        if parser.can_parse(route_path):
            chosen = parser
            break
    if chosen is None:
        chosen = PlasaFallbackParser()
    log.debug(f'Parser {chosen.name} → {route_path.name}')

    chosen.system_tz = system_tz   # naive Log-Zeiten = Image-Zeitzone
    events = chosen.safe_parse(log_file)
    for e in events:
        e.parser_name = chosen.name
        e.source_file = str(log_file)
        e.orig_path   = orig_path
        e.partition   = prov.get('partition', '')
        e.extraction  = prov.get('extraction', '')
    return chosen.name, events


def _find_evtx_files(ctx: PipelineContext) -> List[Path]:
    evtx = []
    search_roots = []
    if ctx.logs_dir_path and ctx.logs_dir_path.is_dir():
        search_roots.append(ctx.logs_dir_path)
    if ctx.case_dir:
        for sub in ['raw/disk_artefakte', 'raw/log_artefakte']:
            p = ctx.case_dir / sub
            if p.is_dir():
                search_roots.append(p)
    for root in search_roots:
        evtx.extend(root.rglob('*.evtx'))
    return list({f.resolve(): f for f in evtx}.values())


_SEVERITY_MAP = {
    'critical':      'critical',
    'high':          'high',
    'medium':        'medium',
    'low':           'info',
    'informational': 'info',
    'info':          'info',
}


def _run_hayabusa(evtx_files: List[Path]) -> List[ForensicEvent]:
    cfg_path = Path(__file__).parent.parent / 'config.yaml'
    try:
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        haya_cfg   = cfg.get('hayabusa', {})
        binary     = haya_cfg.get('binary', '/opt/hayabusa/hayabusa')
        rules_dir  = haya_cfg.get('rules_dir', 'data/sigma-rules/rules/windows')
        min_level  = haya_cfg.get('min_level', 'medium')
    except Exception:
        binary    = '/opt/hayabusa/hayabusa'
        rules_dir = 'data/sigma-rules/rules/windows'
        min_level = 'medium'

    events: List[ForensicEvent] = []
    for evtx_file in tqdm(evtx_files, desc='  Hayabusa', unit='Datei', dynamic_ncols=True):
        try:
            result = subprocess.run(
                [binary, 'csv-timeline',
                 '--file', str(evtx_file),
                 '--rules', rules_dir,
                 '--min-level', min_level,
                 '--no-color', '--quiet'],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode not in (0, 1):
                log.warning(f'  Hayabusa Fehler bei {evtx_file.name}: {result.stderr[:100]}')
                continue
            events.extend(_parse_hayabusa_csv(result.stdout, evtx_file.name))
        except FileNotFoundError:
            log.warning(f'  Hayabusa Binary nicht gefunden: {binary}')
            break
        except subprocess.TimeoutExpired:
            log.warning(f'  Hayabusa Timeout bei {evtx_file.name}')
    return events


def _parse_hayabusa_csv(csv_text: str, source_name: str) -> List[ForensicEvent]:
    events: List[ForensicEvent] = []
    if not csv_text.strip():
        return events
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        try:
            ts_raw = row.get('Datetime', '').strip()
            try:
                ts = datetime.fromisoformat(ts_raw.replace(' +00:00', '+00:00'))
            except ValueError:
                ts = datetime.now(tz=timezone.utc)

            level    = row.get('Level', 'info').strip().lower()
            severity = _SEVERITY_MAP.get(level, 'info')
            message  = (row.get('RuleTitle', '') + ' | ' +
                        row.get('Details', '')).strip(' |')

            events.append(ForensicEvent(
                timestamp  = ts,
                source     = f'hayabusa:{source_name}',
                event_type = 'sigma_match',
                message    = message[:500],
                process    = row.get('Computer', None),
                severity   = severity,
            ))
        except Exception:
            continue
    return events


def _find_log_files(ctx: PipelineContext) -> List[Path]:
    log_files = []

    if ctx.logs_dir_path and ctx.logs_dir_path.is_dir():
        for f in ctx.logs_dir_path.rglob('*'):
            if f.is_file() and not f.name.startswith('.'):
                log_files.append(f)

    if ctx.case_dir:
        log_artefakte = ctx.case_dir / 'raw' / 'log_artefakte'
        if log_artefakte.is_dir():
            for f in log_artefakte.rglob('*'):
                if f.is_file():
                    log_files.append(f)

        # Wiederhergestellte geloeschte Dateien (tsk_recover, Stage 05) —
        # forensisch besonders relevant. Nur log-relevante Pfade aufnehmen,
        # gleiche Filterlogik wie die Extraktion in Stage 05.
        disk_artefakte = ctx.case_dir / 'raw' / 'disk_artefakte'
        if disk_artefakte.is_dir():
            for f in disk_artefakte.rglob('*'):
                if not f.is_file():
                    continue
                rel = f.relative_to(disk_artefakte).as_posix().lower()
                # fuehrenden Partitionsordner (partition_<offset>/) abschneiden
                first, _, rest = rel.partition('/')
                rel_path = rest if first.startswith('partition_') and rest else rel
                if (any(rel_path.startswith(pre) for pre in LOG_PATH_PREFIXES)
                        or any(kw in Path(rel_path).name for kw in LOG_NAME_KEYWORDS)):
                    log_files.append(f)

    log_files = list({f.resolve(): f for f in log_files}.values())
    return log_files
