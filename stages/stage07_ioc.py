import re
import subprocess
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.pipeline_context import PipelineContext
from models.ioc import IOC

log = logging.getLogger(__name__)

IPV4_RE    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
IPV6_RE    = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}')
DOMAIN_RE  = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
URL_RE     = re.compile(r'https?://[^\s\'"<>]+')
MD5_RE     = re.compile(r'\b[0-9a-fA-F]{32}\b')
SHA256_RE  = re.compile(r'\b[0-9a-fA-F]{64}\b')
EMAIL_RE   = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
CVE_RE     = re.compile(r'CVE-\d{4}-\d{4,7}')
REG_RE     = re.compile(r'HKEY_[A-Z_]+\\[^\n\r\'"]+')

PRIVATE_IPS = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.255\.255)'
)

EXTRACTORS = [
    ('ip',         IPV4_RE,   0.9),
    ('ipv6',       IPV6_RE,   0.9),
    ('domain',     DOMAIN_RE, 0.7),
    ('url',        URL_RE,    0.85),
    ('hash_md5',   MD5_RE,    0.8),
    ('hash_sha256',SHA256_RE, 0.85),
    ('email',      EMAIL_RE,  0.9),
    ('cve',        CVE_RE,    0.95),
    ('registry_key', REG_RE,  0.9),
]


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 7: IOC-Extraktion')
    iocs: List[IOC] = []
    seen = set()

    # ── Bulk-Extractor (primär) ────────────────────────────────────────────
    if ctx.disk_image_path and ctx.case_dir:
        bulk_dir = ctx.case_dir / 'raw' / 'bulk_extractor'
        bulk_iocs = _run_bulk_extractor(ctx.disk_image_path, bulk_dir, ctx)
        for ioc in bulk_iocs:
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                iocs.append(ioc)
        log.info(f'  Bulk-Extractor: {len(bulk_iocs)} IOCs')

    # ── Regex-Extraktion (ergänzend aus Events) ────────────────────────────
    sources = _collect_texts(ctx)
    for text, source in sources:
        for ioc_type, pattern, confidence in EXTRACTORS:
            for match in pattern.finditer(text):
                value = match.group(0).strip()
                if not value:
                    continue
                if ioc_type == 'ip' and PRIVATE_IPS.match(value):
                    confidence = 0.4
                key = (ioc_type, value)
                if key in seen:
                    continue
                seen.add(key)
                iocs.append(IOC(
                    type       = ioc_type,
                    value      = value,
                    source     = source,
                    confidence = confidence,
                    context    = text[max(0, match.start()-40):match.end()+40].strip(),
                    timestamp  = datetime.now(tz=timezone.utc),
                ))

    ctx.iocs = iocs
    if ctx.tsk_fallback_used:
        ctx.ioc_quality = 'MITTEL'

    log.info(f'  {len(iocs)} IOCs extrahiert (Qualität: {ctx.ioc_quality})')
    if ctx.coc:
        ctx.coc.add_entry('stage_07', f'IOC-Extraktion: {len(iocs)} IOCs'
                          + (f' (Bulk-Extractor: {ctx.bulk_extractor_iocs})'
                             if ctx.bulk_extractor_ran else ''))
    return ctx


def _run_bulk_extractor(image_path: Path, out_dir: Path,
                        ctx: PipelineContext) -> List[IOC]:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ['bulk_extractor', '-o', str(out_dir), str(image_path)],
            capture_output=True, timeout=1800
        )
        ctx.bulk_extractor_ran = True
    except FileNotFoundError:
        log.warning('  bulk_extractor nicht installiert — Fallback auf Regex')
        return []
    except subprocess.TimeoutExpired:
        log.warning('  bulk_extractor Timeout')
        ctx.bulk_extractor_ran = True

    iocs: List[IOC] = []
    seen: set = set()

    # Mapping: bulk_extractor Dateiname → IOC-Typ + Confidence
    file_map = {
        'ip.txt':       ('ip',          0.85),
        'ip6.txt':      ('ipv6',        0.85),
        'email.txt':    ('email',       0.9),
        'url.txt':      ('url',         0.85),
        'domain.txt':   ('domain',      0.75),
        'md5.txt':      ('hash_md5',    0.8),
        'sha1.txt':     ('hash_sha256', 0.8),
    }

    for fname, (ioc_type, confidence) in file_map.items():
        f = out_dir / fname
        if not f.exists():
            continue
        for line in f.read_text(encoding='utf-8', errors='replace').splitlines():
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 2:
                continue
            value   = parts[1].strip()
            context = parts[2].strip() if len(parts) > 2 else ''
            if not value or (ioc_type, value) in seen:
                continue
            if ioc_type == 'ip' and PRIVATE_IPS.match(value):
                confidence = 0.4
            seen.add((ioc_type, value))
            iocs.append(IOC(
                type       = ioc_type,
                value      = value,
                source     = 'bulk_extractor',
                confidence = confidence,
                context    = context[:100],
                timestamp  = datetime.now(tz=timezone.utc),
            ))

    ctx.bulk_extractor_iocs = len(iocs)
    return iocs


def _collect_texts(ctx: PipelineContext) -> list:
    sources = []

    if ctx.events_db_path and ctx.events_db_path.exists():
        from utils.event_store import EventStore
        with EventStore(ctx.events_db_path) as store:
            for event in store.iter_events():
                sources.append((event.message, event.source))

    for key, lines in ctx.disk_artifacts.items():
        for line in lines:
            sources.append((line, f'dissect:{key}'))

    for key, rows in ctx.memory_results.items():
        for row in rows:
            sources.append((str(row), f'volatility:{key}'))

    for art in ctx.autopsy_results.get('artifacts', []):
        sources.append((str(art.get('value', '')), 'autopsy'))

    return sources
