import logging
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 13: Qualitätsprüfung')
    quality = evaluate_quality(ctx)
    ctx.stage_status['quality'] = quality
    log.info(f'  Gesamtqualität: {quality}')
    log.info(f'  Stufen-Fehler: {len(ctx.stage_errors)}')

    for stage, err in ctx.stage_errors.items():
        log.warning(f'  FEHLER [{stage}]: {err}')

    for stage, status in ctx.stage_status.items():
        log.info(f'  Status [{stage}]: {status}')

    if ctx.coc:
        ctx.coc.add_entry('stage_13', f'Qualität: {quality}, Fehler: {len(ctx.stage_errors)}')
    return ctx


def evaluate_quality(ctx: PipelineContext) -> str:
    error_count = len(ctx.stage_errors)
    if error_count == 0:
        return 'SEHR GUT'
    if error_count <= 2:
        return 'GUT'
    if error_count <= 5:
        return 'EINGESCHRÄNKT'
    return 'KRITISCH'
