import logging
import subprocess
from pathlib import Path
from typing import List

from models.pipeline_context import PipelineContext
from models.event import ForensicEvent
from utils.event_store import EventStore
from parsers import (
    JournaldParser, WtmpParser, UtmpParser, LastlogParser, EVTXParser,
    AuthLogParser, SSHParser, CronParser, AuditParser, Fail2BanParser,
    UFWParser, KernLogParser, BootLogParser, DaemonLogParser, SyslogParser,
    DpkgParser, AptHistoryParser, YumParser, DnfParser, PacmanParser,
    ApacheAccessParser, ApacheErrorParser, NginxAccessParser, NginxErrorParser,
    MySQLErrorParser, PostgreSQLParser, MongoDBParser,
    BashHistoryParser, ZshHistoryParser, FishHistoryParser,
    PostfixMailParser, FTPParser, SambaParser, OpenVPNParser,
    DockerParser, ContainerdParser, IISLogParser, PlasaFallbackParser,
)

log = logging.getLogger(__name__)

ALL_PARSERS = [
    JournaldParser(),
    WtmpParser(),
    UtmpParser(),
    LastlogParser(),
    EVTXParser(),
    AuthLogParser(),
    SSHParser(),
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
    log.info('Stage 3: Log-Parsing')
    log_files = _find_log_files(ctx)
    log.info(f'  {len(log_files)} Log-Dateien gefunden')

    db_path = ctx.output_dir / 'events.db'
    if db_path.exists():
        db_path.unlink()

    total_lines  = 0
    parsed_count = 0
    parser_stats: dict = {}
    batch: List[ForensicEvent] = []

    with EventStore(db_path) as store:
        for lf in log_files:
            events = route_and_parse(lf)
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
        if batch:
            store.insert_events(batch)

    ctx.events_db_path   = db_path
    ctx.parser_stats     = parser_stats
    ctx.total_log_lines  = total_lines
    ctx.parsed_events    = parsed_count
    ctx.events           = []  # Daten leben in events.db

    log.info(f'  {ctx.parsed_events} Events aus {total_lines} Log-Zeilen geparst')
    if ctx.coc:
        ctx.coc.add_entry('stage_03', f'Log-Parsing: {ctx.parsed_events} Events')
    return ctx


def route_and_parse(log_file: Path) -> List[ForensicEvent]:
    for parser in ALL_PARSERS:
        if parser.name == 'plaso_fallback':
            continue
        if parser.can_parse(log_file):
            log.debug(f'Parser {parser.name} → {log_file.name}')
            return parser.safe_parse(log_file)
    log.debug(f'Plaso Fallback → {log_file.name}')
    return PlasaFallbackParser().safe_parse(log_file)


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

    log_files = list({f.resolve(): f for f in log_files}.values())
    return log_files
