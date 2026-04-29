#!/usr/bin/env python3
"""
DFIR Analyse-Pipeline v3.0
Verwendung: python pipeline.py <image> [--ram <dump>] [--logs <dir>] [--output_dir <dir>]
"""
import argparse
import logging
import sys
from pathlib import Path

from models.pipeline_context import PipelineContext
from utils.logger import get_logger

from stages import (
    stage01_detection,
    stage02_memory,
    stage03_profiling,
    stage04_logs,
    stage05_disk,
    stage05_1_autopsy,
    stage06_ioc,
    stage07_tsk,
    stage08_normalize,
    stage09_antiforensics,
    stage10_ml,
    stage11_mitre,
    stage12_aggregation,
    stage13_quality,
    stage14_export,
)

log = get_logger('pipeline')
logging.basicConfig(level=logging.INFO)


def run_stage(stage_fn, ctx: PipelineContext, stage_name: str,
              **kwargs) -> PipelineContext:
    try:
        if ctx.coc:
            ctx.coc.add_entry(stage_name, 'gestartet')
        result = stage_fn(ctx, **kwargs) if kwargs else stage_fn(ctx)
        ctx.stage_status[stage_name] = 'OK'
        if ctx.coc:
            ctx.coc.add_entry(stage_name, 'abgeschlossen')
        return result
    except Exception as e:
        ctx.stage_errors[stage_name] = str(e)
        ctx.stage_status[stage_name] = 'FEHLER'
        if ctx.coc:
            ctx.coc.add_entry(stage_name, f'FEHLER: {e}')
        log.error(f'Stufe {stage_name} fehlgeschlagen: {e}')
        return ctx


def main():
    parser = argparse.ArgumentParser(
        description='DFIR Analyse-Pipeline v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('image',         help='Pfad zum Disk-Image (.E01, .dd, .vmdk, .raw)')
    parser.add_argument('--ram',         help='Pfad zum RAM-Dump (.raw, .dmp, .mem)')
    parser.add_argument('--logs',        help='Pfad zum Log-Ordner')
    parser.add_argument('--output_dir',  default='./output', help='Ausgabe-Verzeichnis')
    parser.add_argument('--force-autopsy', action='store_true', help='Autopsy erzwingen')
    parser.add_argument('--no-autopsy',    action='store_true', help='Autopsy deaktivieren')
    parser.add_argument('--no-timesketch', action='store_true', help='Timesketch-Upload deaktivieren')
    parser.add_argument('--debug',         action='store_true', help='Debug-Logging aktivieren')
    parser.add_argument('--workers',       type=int, default=2,
                        help='Anzahl paralleler Worker für Stage 6 + Stage 5 (Standard: 2)')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    image_path = Path(args.image)
    if not image_path.exists():
        log.error(f'Image nicht gefunden: {image_path}')
        sys.exit(1)

    ctx = PipelineContext(
        disk_image_path = image_path,
        ram_dump_path   = Path(args.ram)  if args.ram  else None,
        logs_dir_path   = Path(args.logs) if args.logs else None,
        output_dir      = Path(args.output_dir),
        workers         = args.workers,
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)

    log.info('=' * 60)
    log.info('  DFIR Analyse-Pipeline v3.0')
    log.info(f'  Image: {image_path}')
    log.info('=' * 60)

    # ── Pipeline ausführen ────────────────────────────────────────────────────
    ctx = run_stage(stage01_detection.run,      ctx, 'stage_01')
    ctx = run_stage(stage02_memory.run,         ctx, 'stage_02')
    ctx = run_stage(stage03_profiling.run,      ctx, 'stage_03')
    ctx = run_stage(stage05_disk.run,           ctx, 'stage_05')
    ctx = run_stage(stage05_1_autopsy.run,      ctx, 'stage_05_1',
                    force=args.force_autopsy, skip=args.no_autopsy)
    ctx = run_stage(stage07_tsk.run,            ctx, 'stage_07')
    ctx = run_stage(stage04_logs.run,           ctx, 'stage_04')
    ctx = run_stage(stage06_ioc.run,            ctx, 'stage_06')
    ctx = run_stage(stage08_normalize.run,      ctx, 'stage_08')
    ctx = run_stage(stage09_antiforensics.run,  ctx, 'stage_09')
    ctx = run_stage(stage10_ml.run,             ctx, 'stage_10')
    ctx = run_stage(stage11_mitre.run,          ctx, 'stage_11')
    ctx = run_stage(stage12_aggregation.run,    ctx, 'stage_12')
    ctx = run_stage(stage13_quality.run,        ctx, 'stage_13')
    ctx = run_stage(stage14_export.run,         ctx, 'stage_14')

    # ── Ergebnis ausgeben ────────────────────────────────────────────────────
    from stages.stage13_quality import evaluate_quality
    quality = evaluate_quality(ctx)

    log.info('=' * 60)
    log.info('  ANALYSE ABGESCHLOSSEN')
    log.info(f'  Qualität:   {quality}')
    log.info(f'  Events:     {ctx.parsed_events:,}')
    log.info(f'  IOCs:       {len(ctx.iocs)}')
    log.info(f'  MITRE:      {len(ctx.mitre_hits)} Techniken')
    log.info(f'  Anomalien:  {len(ctx.anomalies)}')
    log.info(f'  Ausgabe:    {ctx.case_dir}')
    log.info('=' * 60)

    if ctx.enriched_summary:
        print('\n' + ctx.enriched_summary)

    return 0 if not ctx.stage_errors else 1


if __name__ == '__main__':
    sys.exit(main())
