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
from utils.rich_ui import PipelineUI

from stages import (
    stage01_detection,
    stage02_memory,
    stage03_profiling,
    stage04_disk,
    stage04_1_autopsy,
    stage05_tsk,
    stage06_logs,
    stage07_ioc,
    stage08_normalize,
    stage09_antiforensics,
    stage10_ml,
    stage11_mitre,
    stage12_aggregation,
    stage13_quality,
    stage14_export,
)

log = get_logger('pipeline')
logging.basicConfig(level=logging.WARNING)   # UI zeigt Status — nur Warnungen/Fehler ins Log


def run_stage(stage_fn, ctx: PipelineContext, stage_name: str,
              ui: PipelineUI, **kwargs) -> PipelineContext:
    ui.stage_start(stage_name)
    try:
        if ctx.coc:
            ctx.coc.add_entry(stage_name, 'gestartet')
        result = stage_fn(ctx, **kwargs) if kwargs else stage_fn(ctx)
        ctx.stage_status[stage_name] = 'OK'
        if ctx.coc:
            ctx.coc.add_entry(stage_name, 'abgeschlossen')

        # Übersprungen-Erkennung anhand stage_status
        raw = ctx.stage_status.get(stage_name, 'OK')
        if 'ÜBERSPRUNGEN' in raw:
            ui.stage_done(stage_name, status='skipped')
        else:
            # Kurze Zusatzinfo pro Stage
            notes = {
                'stage_01': f'{ctx.file_type}  {ctx.file_size_gb:.1f} GB',
                'stage_02': f'{sum(len(v) for v in ctx.memory_results.values()):,} Einträge',
                'stage_03': ctx.os_name or '',
                'stage_04': f'{sum(len(v) for v in ctx.disk_artifacts.values()):,} Artefakte',
                'stage_06': f'{ctx.parsed_events:,} Events',
                'stage_07': f'{len(ctx.iocs)} IOCs',
                'stage_08': f'{len(ctx.normalized_events):,} Events normalisiert',
                'stage_09': f'{len(ctx.antiforensics_hits)} Treffer',
                'stage_10': f'{len(ctx.anomalies)} Anomalien',
                'stage_11': f'{len(ctx.mitre_hits)} Techniken',
            }
            ui.stage_done(stage_name, status='ok', note=notes.get(stage_name, 'OK'))
        return result

    except Exception as e:
        ctx.stage_errors[stage_name]  = str(e)
        ctx.stage_status[stage_name]  = 'FEHLER'
        if ctx.coc:
            ctx.coc.add_entry(stage_name, f'FEHLER: {e}')
        log.error(f'Stufe {stage_name} fehlgeschlagen: {e}')
        ui.stage_done(stage_name, status='error')
        return ctx


def main():
    parser = argparse.ArgumentParser(
        description='DFIR Analyse-Pipeline v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('image',           help='Pfad zum Disk-Image (.E01, .dd, .vmdk, .raw)')
    parser.add_argument('--ram',           help='Pfad zum RAM-Dump (.raw, .dmp, .mem)')
    parser.add_argument('--logs',          help='Pfad zum Log-Ordner')
    parser.add_argument('--output_dir',    default='./output', help='Ausgabe-Verzeichnis')
    parser.add_argument('--force-autopsy', action='store_true', help='Autopsy erzwingen')
    parser.add_argument('--no-autopsy',    action='store_true', help='Autopsy deaktivieren')
    parser.add_argument('--no-timesketch',     action='store_true', help='Timesketch-Upload deaktivieren')
    parser.add_argument('--no-bulk-extractor', action='store_true', help='Bulk-Extractor deaktivieren')
    parser.add_argument('--no-mactime',        action='store_true', help='MACtime + Sorter deaktivieren')
    parser.add_argument('--debug',             action='store_true', help='Debug-Logging aktivieren')
    parser.add_argument('--workers',           type=int, default=2,
                        help='Anzahl paralleler Worker für Stage 6 + Stage 5 (Standard: 2)')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    image_path = Path(args.image)
    if not image_path.exists():
        print(f'[Fehler] Image nicht gefunden: {image_path}')
        sys.exit(1)

    ctx = PipelineContext(
        disk_image_path = image_path,
        ram_dump_path   = Path(args.ram)  if args.ram  else None,
        logs_dir_path   = Path(args.logs) if args.logs else None,
        output_dir      = Path(args.output_dir),
        workers         = args.workers,
        skip_bulk_extractor = args.no_bulk_extractor,
        skip_mactime        = args.no_mactime,
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)

    ui = PipelineUI(image_name=image_path.name)
    ui.start()

    try:
        # ── Pipeline ausführen — Panel direkt nach jeder Stage ────────────────
        ctx = run_stage(stage01_detection.run,     ctx, 'stage_01',   ui)
        ui.show_stage01_detail(ctx)

        ctx = run_stage(stage02_memory.run,        ctx, 'stage_02',   ui)
        ui.show_stage02_detail(ctx)

        ctx = run_stage(stage03_profiling.run,     ctx, 'stage_03',   ui)
        ui.show_stage03_detail(ctx)

        ctx = run_stage(stage04_disk.run,          ctx, 'stage_04',   ui)
        ctx = run_stage(stage04_1_autopsy.run,     ctx, 'stage_04_1', ui,
                        force=args.force_autopsy, skip=args.no_autopsy)

        ctx = run_stage(stage05_tsk.run,           ctx, 'stage_05',   ui)
        ui.show_stage05_detail(ctx)

        ctx = run_stage(stage06_logs.run,          ctx, 'stage_06',   ui)
        ui.show_parser_detail(ctx)
        # MACtime nach Stage 6 — events.db existiert jetzt
        ctx = stage05_tsk.run_mactime_after_stage6(ctx)

        ctx = run_stage(stage07_ioc.run,           ctx, 'stage_07',   ui)
        ui.show_stage07_detail(ctx)

        ctx = run_stage(stage08_normalize.run,     ctx, 'stage_08',   ui)
        ui.show_stage08_detail(ctx)

        ctx = run_stage(stage09_antiforensics.run, ctx, 'stage_09',   ui)
        ui.show_stage09_detail(ctx)

        ctx = run_stage(stage10_ml.run,            ctx, 'stage_10',   ui)
        ctx = run_stage(stage11_mitre.run,         ctx, 'stage_11',   ui)

        ctx = run_stage(stage12_aggregation.run,   ctx, 'stage_12',   ui)
        ui.show_stage12_detail(ctx)

        ctx = run_stage(stage13_quality.run,       ctx, 'stage_13',   ui)
        ui.show_stage13_detail(ctx)

        ctx = run_stage(stage14_export.run,        ctx, 'stage_14',   ui)
        ui.show_stage14_detail(ctx)

    finally:
        ui.stop()

    # ── Abschluss-Zusammenfassung ─────────────────────────────────────────────
    ui.show_summary(ctx)

    return 0 if not ctx.stage_errors else 1


if __name__ == '__main__':
    sys.exit(main())
