import logging
import re
from pathlib import Path
from typing import List, Dict

from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

TIMESTOMPING_KEYWORDS = ['timestomp', 'touch -t', 'setfiletime', '$si', '$fn']
LOG_WIPE_KEYWORDS     = ['> /var/log', 'truncate -s 0', 'rm -f /var/log',
                          'echo "" > /var/log', 'shred /var/log', '> /dev/null 2>&1']
ROOTKIT_KEYWORDS      = ['insmod', 'modprobe', 'ld_preload', '/proc/kcore',
                          'ptrace', 'sys_call_table']
ADS_PATTERN           = re.compile(r'\w+:\w+')  # NTFS ADS: file:stream
SECURE_DELETE_TOOLS   = ['shred', 'srm', 'wipe', 'bleachbit', 'dd if=/dev/zero',
                          'dd if=/dev/urandom']


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 7: Anti-Forensics-Erkennung')
    hits: List[Dict] = []

    hits += _check_timestomping(ctx)
    hits += _check_log_wiping(ctx)
    hits += _check_rootkit_indicators(ctx)
    hits += _check_secure_delete(ctx)
    hits += _check_yara(ctx)

    ctx.antiforensics_hits = hits
    log.info(f'  {len(hits)} Anti-Forensics-Treffer gefunden')
    if ctx.coc:
        ctx.coc.add_entry('stage_07', f'Anti-Forensics: {len(hits)} Treffer')
    return ctx


def _check_timestomping(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in ctx.normalized_events:
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in TIMESTOMPING_KEYWORDS):
            hits.append({
                'type':     'timestomping',
                'file':     event.file_path or 'unbekannt',
                'details':  event.message[:200],
                'severity': 'high',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    return hits


def _check_log_wiping(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in ctx.normalized_events:
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in LOG_WIPE_KEYWORDS):
            hits.append({
                'type':     'log_deletion',
                'file':     event.file_path or '/var/log/*',
                'details':  event.message[:200],
                'severity': 'critical',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    for key, lines in ctx.disk_artifacts.items():
        for line in lines:
            if any(kw in line.lower() for kw in LOG_WIPE_KEYWORDS):
                hits.append({
                    'type':     'log_deletion',
                    'file':     line.strip()[:100],
                    'details':  f'Dissect-Fund: {line[:100]}',
                    'severity': 'high',
                    'source':   f'dissect:{key}',
                    'timestamp':'',
                })
    return hits


def _check_rootkit_indicators(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in ctx.normalized_events:
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in ROOTKIT_KEYWORDS):
            hits.append({
                'type':     'rootkit_indicator',
                'file':     event.file_path or 'unbekannt',
                'details':  event.message[:200],
                'severity': 'critical',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    for plugin, rows in ctx.memory_results.items():
        for row in rows:
            row_str = str(row).lower()
            if 'hidden' in row_str or 'injected' in row_str or 'malfind' in plugin:
                hits.append({
                    'type':     'rootkit_indicator',
                    'file':     str(row)[:80],
                    'details':  f'Volatility {plugin}: {str(row)[:150]}',
                    'severity': 'critical',
                    'source':   f'volatility:{plugin}',
                    'timestamp':'',
                })
    return hits


def _check_secure_delete(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in ctx.normalized_events:
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in SECURE_DELETE_TOOLS):
            hits.append({
                'type':     'secure_delete',
                'file':     event.file_path or 'unbekannt',
                'details':  event.message[:200],
                'severity': 'high',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    return hits


def _check_yara(ctx: PipelineContext) -> List[Dict]:
    hits = []
    rules_dir = Path(__file__).parent.parent / 'data' / 'yara-rules'
    if not rules_dir.exists():
        return hits
    try:
        import yara
        rule_files = {f.stem: str(f) for f in rules_dir.rglob('*.yar')}
        if not rule_files:
            return hits
        rules = yara.compile(filepaths=rule_files)

        case_dir = ctx.case_dir
        if not case_dir or not case_dir.exists():
            return hits

        for target in case_dir.rglob('*'):
            if not target.is_file() or target.stat().st_size > 50_000_000:
                continue
            try:
                matches = rules.match(str(target), timeout=30)
                for match in matches:
                    hits.append({
                        'type':     'yara_match',
                        'file':     str(target),
                        'details':  f'YARA-Regel: {match.rule} Tags: {match.tags}',
                        'severity': 'high',
                        'source':   'yara',
                        'timestamp':'',
                        'rule':     match.rule,
                    })
            except Exception:
                continue
    except ImportError:
        log.warning('yara-python nicht installiert — YARA-Scan übersprungen')
    return hits
