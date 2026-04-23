import logging
from models.pipeline_context import PipelineContext
from utils.timestamp import to_utc

log = logging.getLogger(__name__)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 6: Datennormalisierung — alle Timestamps → UTC')
    normalized = []

    for event in ctx.events:
        try:
            event.timestamp = to_utc(str(event.timestamp), ctx.timezone)
        except Exception:
            pass
        if not event.source:
            event.source = 'unknown'
        if not event.event_type:
            event.event_type = 'generic'
        if not event.severity:
            event.severity = 'info'
        normalized.append(event)

    ctx.normalized_events = sorted(normalized, key=lambda e: e.timestamp)
    log.info(f'  {len(ctx.normalized_events)} Events normalisiert und sortiert (UTC)')

    if ctx.coc:
        ctx.coc.add_entry('stage_06', f'Normalisierung: {len(ctx.normalized_events)} Events → UTC')
    return ctx
