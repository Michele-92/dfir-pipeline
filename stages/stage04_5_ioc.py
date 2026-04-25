import re
import logging
from datetime import datetime, timezone
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
    log.info('Stage 4.5: IOC-Extraktion')
    iocs: List[IOC] = []
    seen = set()

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
        ctx.coc.add_entry('stage_04_5', f'IOC-Extraktion: {len(iocs)} IOCs')
    return ctx


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
