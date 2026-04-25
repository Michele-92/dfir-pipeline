import logging
from models.pipeline_context import PipelineContext
from utils.event_store import EventStore
from utils.timestamp import to_utc

log = logging.getLogger(__name__)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 6: Datennormalisierung — alle Timestamps → UTC')

    tz = ctx.timezone

    def _to_utc_str(ts_str: str) -> str:
        try:
            return to_utc(ts_str, tz).isoformat()
        except Exception:
            return ts_str

    with EventStore(ctx.events_db_path) as store:
        total = store.count()
        log.info(f'  Normalisiere {total:,} Events per SQL-UPDATE...')
        store.normalize_timestamps(_to_utc_str)
        log.info(f'  Lade {total:,} Events in Speicher...')
        ctx.normalized_events = store.get_all_sorted()

    count = len(ctx.normalized_events)
    log.info(f'  {count:,} Events normalisiert und sortiert (UTC)')

    if ctx.coc:
        ctx.coc.add_entry('stage_06', f'Normalisierung: {count} Events → UTC')
    return ctx
