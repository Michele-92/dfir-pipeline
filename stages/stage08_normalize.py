import logging
from datetime import datetime, timezone
from models.pipeline_context import PipelineContext
from utils.event_store import EventStore
from utils.timestamp import to_utc

log = logging.getLogger(__name__)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 8: Datennormalisierung — alle Timestamps → UTC')

    tz = ctx.timezone

    # Review-Fix CRITICAL #6: Timestamps sind bereits in den Parsern korrekt
    # nach UTC normalisiert (mit der Image-Zeitzone aus Stage 03). Die
    # fruehere zweite Konversion hier verschob UTC-Quellen (mactime, wtmp,
    # journald, audit, hayabusa) faelschlich um den Zeitzonen-Offset.
    with EventStore(ctx.events_db_path) as store:
        total = store.count()
        log.info(f'  Bereinige Pflichtfelder ({total:,} Events)...')
        store.cleanup_required_fields()
        log.info(f'  Lade {total:,} Events in Speicher...')
        ctx.normalized_events = store.get_all_sorted()

    count = len(ctx.normalized_events)

    # UTC-Offset der Systemzeitzone berechnen
    try:
        import pytz
        sys_tz  = pytz.timezone(tz)
        now_utc = datetime.now(timezone.utc)
        offset  = sys_tz.utcoffset(now_utc)
        total_seconds = int(offset.total_seconds())
        hours, remainder = divmod(abs(total_seconds), 3600)
        minutes = remainder // 60
        sign = '+' if total_seconds >= 0 else '-'
        ctx.timezone_offset = f'UTC{sign}{hours:02d}:{minutes:02d}'
    except Exception:
        ctx.timezone_offset = 'UTC'

    # Fruehestes/letztes Event — Epoch-Marker (ts_invalid) und
    # Vor-1990-Artefakte nicht als 'Erste Aktivitaet' ausweisen
    _valid = [e for e in ctx.normalized_events if e.timestamp.year >= 1990]
    if _valid:
        def _fmt(event) -> str:
            utc_str   = event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
            try:
                local_ts  = event.timestamp.astimezone(pytz.timezone(tz))
                local_str = local_ts.strftime('%H:%M:%S')
                return f'{utc_str}  ({local_str} {tz})'
            except Exception:
                return utc_str

        ctx.earliest_event = _fmt(_valid[0])
        ctx.latest_event   = _fmt(_valid[-1])

    log.info(f'  {count:,} Events normalisiert und sortiert')
    log.info(f'  Systemzeitzone: {tz} ({ctx.timezone_offset})')

    if ctx.coc:
        ctx.coc.add_entry('stage_08',
            f'Normalisierung: {count} Events → UTC | Systemzeitzone: {tz} ({ctx.timezone_offset})')
    return ctx
