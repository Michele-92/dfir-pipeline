import logging
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 12: Ergebnis-Aggregation')
    ctx.enriched_summary = _build_summary(ctx)
    log.info('  Zusammenfassung erstellt')
    if ctx.coc:
        ctx.coc.add_entry('stage_12', 'Ergebnis-Aggregation abgeschlossen')
    return ctx


def _build_summary(ctx: PipelineContext) -> str:
    lines = []

    lines.append(f'=== DFIR ANALYSE-ZUSAMMENFASSUNG ===')
    lines.append(f'System: {ctx.os_name or "Unbekannt"} | Hostname: {ctx.hostname or "Unbekannt"}')
    lines.append(f'Image: {ctx.disk_image_path.name if ctx.disk_image_path else "?"} '
                 f'({ctx.file_size_gb:.1f} GB, {ctx.file_type})')
    lines.append('')

    lines.append(f'STATISTIKEN:')
    lines.append(f'  Log-Zeilen gesamt:  {ctx.total_log_lines:,}')
    lines.append(f'  Geparste Events:    {ctx.parsed_events:,}')
    lines.append(f'  Anomalien (ML):     {len(ctx.anomalies)}')
    lines.append(f'  IOCs gefunden:      {len(ctx.iocs)}')
    lines.append(f'  MITRE-Techniken:    {len(ctx.mitre_hits)}')
    lines.append(f'  Anti-Forensics:     {len(ctx.antiforensics_hits)}')
    lines.append('')

    if ctx.mitre_hits:
        lines.append('TOP MITRE ATT&CK TECHNIKEN:')
        for hit in sorted(ctx.mitre_hits, key=lambda h: h['confidence'], reverse=True)[:5]:
            lines.append(f'  [{hit["technique_id"]}] {hit["technique_name"]} '
                         f'(Confidence: {hit["confidence"]:.0%})')
        lines.append('')

    critical_events = [e for e in ctx.normalized_events if e.severity == 'critical']
    high_events     = [e for e in ctx.normalized_events if e.severity == 'high']
    if critical_events or high_events:
        lines.append(f'KRITISCHE FUNDE: {len(critical_events)} KRITISCH, {len(high_events)} HOCH')
        for e in (critical_events + high_events)[:3]:
            lines.append(f'  [{e.timestamp.strftime("%Y-%m-%d %H:%M:%S")}] '
                         f'{e.source}: {e.message[:120]}')
        lines.append('')

    if ctx.antiforensics_hits:
        lines.append(f'ANTI-FORENSICS WARNUNG: {len(ctx.antiforensics_hits)} Techniken erkannt!')
        for h in ctx.antiforensics_hits[:3]:
            lines.append(f'  {h["type"].upper()}: {h["details"][:100]}')
        lines.append('')

    if ctx.stage_errors:
        lines.append(f'STUFEN-FEHLER: {len(ctx.stage_errors)}')
        for stage, err in ctx.stage_errors.items():
            lines.append(f'  {stage}: {err[:80]}')

    return '\n'.join(lines)
