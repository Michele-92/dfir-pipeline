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
from utils.reexport import (
    save_ctx_snapshot,
    list_available_runs,
    create_reexport_dir,
    reconstruct_ctx,
)

from stages import (
    stage01_detection,
    # stage02_memory,
    stage02_partition_layout,
    stage03_profiling,
    stage035_basic_checks,
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
    stage_timeline_analysis,
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
                'stage_01':   f'{ctx.file_type}  {ctx.file_size_gb:.1f} GB  [{ctx.hash_source}]',
                'stage_02':   f'{len(ctx.partition_layout)} Partitionen  {len(ctx.analysis_partitions)} analysierbar',
                'stage_03':   ctx.os_name or '',
                'stage_03_5': f'{ctx.basic_check_anomalies} Anomalien',
                'stage_04':   f'{sum(len(v) for v in ctx.disk_artifacts.values()):,} Artefakte',
                'stage_06':   f'{ctx.parsed_events:,} Events',
                'stage_07':   f'{len(ctx.iocs)} IOCs',
                'stage_08':   f'{len(ctx.normalized_events):,} Events normalisiert',
                'stage_09':   f'{len(ctx.antiforensics_hits)} Treffer',
                'stage_10':   f'{len(ctx.anomalies)} Anomalien',
                'stage_11':   f'{len(ctx.mitre_hits)} Techniken',
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
    parser.add_argument('image', nargs='?', default=None,
                        help='Pfad zum Disk-Image (.E01, .dd, .vmdk, .raw) — weglassen für Reexport-Modus')
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
    parser.add_argument('--case-mode',
                        choices=['ask', 'select', 'batch', 'combined'],
                        default='ask',
                        help='Verhalten bei Ordner mit MEHREREN Images: '
                             'ask=interaktiv fragen | select=einzeln auswaehlen | '
                             'batch=alle als getrennte Faelle | '
                             'combined=alle als EIN Fall (gemeinsamer Report)')
    parser.add_argument('--max-read-mb',       type=int, default=50,
                        help='Max. MB pro Log-Datei in Stage 6 (entpackt). '
                             '0 = unbegrenzt. Faustregel RAM-Bedarf: '
                             'Worker x 4 x diesem Wert (Standard: 50)')
    parser.add_argument('--mode', choices=['auto', 'manual'], default='auto',
                        help='auto=vollautomatisch | manual=Kontrollmodus mit Tool-Auswahl pro Partition')
    parser.add_argument('--yara', choices=['custom', 'linux', 'full'], default='custom',
                        help='custom=nur eigene Regeln (schnell) | linux=Linux-relevante Regeln | full=alle 1264 Regeln')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    output_dir = Path(args.output_dir)

    # ── Ordner-Eingabe: Disk-Images erkennen (Multi-Image-Modus) ─────────────
    # Datei direkt / Ordner mit 1 Image (auch segmentiert) -> laeuft normal.
    # Nur bei einem Ordner mit MEHREREN Images erscheint die Auswahl.
    batch_images: list = []
    if args.image and Path(args.image).is_dir():
        result = _resolve_folder_input(Path(args.image), args.case_mode)
        if isinstance(result, dict) and result.get('combined'):
            # Fall-Modus: alle Images -> EIN gemeinsamer Report
            return _run_case_pipeline(args, result['images'], output_dir)
        elif isinstance(result, list):
            batch_images = result
        else:
            args.image = str(result)

    # ── Batch: alle Images nacheinander als GETRENNTE Faelle ────────────────
    if batch_images:
        print()
        print(f'  Batch-Modus: {len(batch_images)} Images werden nacheinander analysiert.')
        rc_total = 0
        for i, img in enumerate(batch_images, 1):
            print()
            print(f'  ━━━ Image {i}/{len(batch_images)}: {img.name} ━━━')
            rc_total = max(rc_total, _run_pipeline(args, img, output_dir))
        print()
        print(f'  Batch abgeschlossen — {len(batch_images)} Images analysiert.')
        return rc_total

    # ── Startmodus — immer fragen ─────────────────────────────────────────────
    choice = _show_startup_menu(output_dir, args.image)

    if choice == 'reexport':
        return _run_reexport_flow(output_dir)

    # Neuer Testlauf gewählt
    if args.image is None:
        print()
        print('  [Fehler] Kein Image angegeben.')
        print('  Starte mit:  python pipeline.py <image.E01>')
        print()
        sys.exit(1)

    image_path = Path(args.image)
    if not image_path.exists():
        print(f'[Fehler] Image nicht gefunden: {image_path}')
        sys.exit(1)

    return _run_pipeline(args, image_path, output_dir)


# Per-Image-Felder, die in den Snapshot eines Beweisstuecks gehoeren
_EVIDENCE_SNAPSHOT_FIELDS = (
    'file_type', 'file_size_gb', 'md5', 'sha1', 'sha256', 'hash_source',
    'os_name', 'os_family', 'kernel_version', 'hostname', 'machine_id',
    'shadow_mtime', 'timezone', 'timezone_display',
    'partition_layout', 'partition_profiles', 'analysis_partitions',
    'basic_checks', 'basic_check_anomalies', 'ip_addresses',
)


def _run_case_pipeline(args, images: list, output_dir: Path) -> int:
    """Fall-Modus: mehrere Images -> EIN gemeinsamer Report.

    Stage 1-5 + 3.5 laufen PRO Image (eigene Hashes, CoC-Eintrag,
    Partitionen, Profil, Extraktion nach raw/*/<evidence>/). Stage 6-14
    laufen EINMAL ueber die gemeinsame events.db -> eine Timeline,
    Cross-Host-Korrelation, ein Report mit Systemprofil je Image.
    """
    import copy
    output_dir.mkdir(parents=True, exist_ok=True)
    ctx = PipelineContext(
        ram_dump_path   = Path(args.ram)  if args.ram  else None,
        logs_dir_path   = Path(args.logs) if args.logs else None,
        output_dir      = output_dir,
        workers         = args.workers,
        skip_bulk_extractor = args.no_bulk_extractor,
        skip_mactime        = args.no_mactime,
        interactive_mode    = (args.mode == 'manual'),
        yara_mode           = args.yara,
        max_read_mb         = args.max_read_mb,
        combined_case       = True,
    )

    print()
    print(f'  ╔══════════════════════════════════════════════════════════════╗')
    print(f'  ║  FALL-MODUS: {len(images)} Images werden als EIN Fall analysiert'.ljust(67) + '║')
    print(f'  ╚══════════════════════════════════════════════════════════════╝')

    ui = PipelineUI(image_name=f'Fall ({len(images)} Images)')
    ui.start()
    try:
        # ── Phase 1: Stage 1-5 + 3.5 pro Image ───────────────────────────
        for i, img in enumerate(images, 1):
            label = img.name
            print()
            print(f'  ━━━ Image {i}/{len(images)}: {label} — Erfassung & Extraktion ━━━')
            ctx.disk_image_path = img
            ctx.evidence_label  = label
            # per-Image-Akkumulator zuruecksetzen (Basic Checks sauber je Image)
            ctx.tsk_extracted_filenames = []

            ctx = run_stage(stage01_detection.run,        ctx, 'stage_01', ui)
            ui.show_stage01_detail(ctx)
            ctx = run_stage(stage02_partition_layout.run, ctx, 'stage_02', ui)
            ui.show_stage02_partition_detail(ctx)
            ctx = run_stage(stage03_profiling.run,        ctx, 'stage_03', ui)
            ui.show_stage03_detail(ctx)
            ctx = run_stage(stage05_tsk.run,              ctx, 'stage_05', ui)
            ui.show_stage05_detail(ctx)
            ctx = run_stage(stage035_basic_checks.run,    ctx, 'stage_03_5', ui)
            ui.show_stage035_detail(ctx)

            # Snapshot dieses Beweisstuecks (tiefe Kopie der Per-Image-Felder)
            snap = {'name': label, 'path': str(img)}
            for f in _EVIDENCE_SNAPSHOT_FIELDS:
                snap[f] = copy.deepcopy(getattr(ctx, f, None))
            ctx.evidence_items.append(snap)

        # ── Phase 2: Stage 6-14 EINMAL ueber alle Images ─────────────────
        print()
        print(f'  ━━━ Gemeinsame Analyse aller {len(images)} Images ━━━')
        ctx = run_stage(stage06_logs.run,          ctx, 'stage_06', ui)
        ui.show_parser_detail(ctx)
        ctx = stage05_tsk.run_mactime_after_stage6(ctx)
        ui.show_mactime_sorter_detail(ctx)
        ctx = run_stage(stage07_ioc.run,           ctx, 'stage_07', ui)
        ui.show_stage07_detail(ctx)
        ctx = run_stage(stage08_normalize.run,     ctx, 'stage_08', ui)
        ui.show_stage08_detail(ctx)
        ctx = run_stage(stage09_antiforensics.run, ctx, 'stage_09', ui)
        ui.show_stage09_detail(ctx)
        ctx = run_stage(stage_timeline_analysis.run, ctx, 'stage_8.5', ui)
        ui.show_stage85_detail(ctx)
        ctx = run_stage(stage13_quality.run,       ctx, 'stage_13', ui)
        ui.show_stage13_detail(ctx)
        try:
            save_ctx_snapshot(ctx, ctx.case_dir)
        except Exception as e:
            log.warning(f'  Snapshot fehlgeschlagen: {e} — Stage 14 laeuft trotzdem')
        ctx = run_stage(stage14_export.run,        ctx, 'stage_14', ui)
        ui.show_stage14_detail(ctx)
    finally:
        ui.stop()

    ui.show_summary(ctx)
    print()
    print(f'  ✅  Fall-Report erstellt: {ctx.case_dir}')
    return 0 if not ctx.stage_errors else 1


def _run_pipeline(args, image_path: Path, output_dir: Path) -> int:
    """Fuehrt die komplette Pipeline fuer EIN Image aus."""
    ctx = PipelineContext(
        disk_image_path = image_path,
        ram_dump_path   = Path(args.ram)  if args.ram  else None,
        logs_dir_path   = Path(args.logs) if args.logs else None,
        output_dir      = output_dir,
        workers         = args.workers,
        skip_bulk_extractor = args.no_bulk_extractor,
        skip_mactime        = args.no_mactime,
        interactive_mode    = (args.mode == 'manual'),
        yara_mode           = args.yara,
        max_read_mb         = args.max_read_mb,
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)

    ui = PipelineUI(image_name=image_path.name)
    ui.start()

    try:
        # ── Pipeline ausführen — Panel direkt nach jeder Stage ────────────────
        ctx = run_stage(stage01_detection.run,          ctx, 'stage_01',     ui)
        ui.show_stage01_detail(ctx)

        # ctx = run_stage(stage02_memory.run,             ctx, 'stage_02_mem', ui)
        # ui.show_stage02_detail(ctx)

        ctx = run_stage(stage02_partition_layout.run,   ctx, 'stage_02',     ui)
        ui.show_stage02_partition_detail(ctx)

        ctx = run_stage(stage03_profiling.run,          ctx, 'stage_03',   ui)
        ui.show_stage03_detail(ctx)

        # ctx = run_stage(stage04_disk.run,          ctx, 'stage_04',   ui)
        # ctx = run_stage(stage04_1_autopsy.run,     ctx, 'stage_04_1', ui,
        #                 force=args.force_autopsy, skip=args.no_autopsy)

        ctx = run_stage(stage05_tsk.run,           ctx, 'stage_05',   ui)
        ui.show_stage05_detail(ctx)

        ctx = run_stage(stage035_basic_checks.run,      ctx, 'stage_03_5', ui)
        ui.show_stage035_detail(ctx)

        ctx = run_stage(stage06_logs.run,          ctx, 'stage_06',   ui)
        ui.show_parser_detail(ctx)
        # MACtime + Sorter nach Stage 6 — events.db existiert jetzt
        ctx = stage05_tsk.run_mactime_after_stage6(ctx)
        ui.show_mactime_sorter_detail(ctx)

        ctx = run_stage(stage07_ioc.run,           ctx, 'stage_07',   ui)
        ui.show_stage07_detail(ctx)

        ctx = run_stage(stage08_normalize.run,     ctx, 'stage_08',   ui)
        ui.show_stage08_detail(ctx)

        ctx = run_stage(stage09_antiforensics.run, ctx, 'stage_09',   ui)
        ui.show_stage09_detail(ctx)

        ctx = run_stage(stage_timeline_analysis.run, ctx, 'stage_8.5', ui)
        ui.show_stage85_detail(ctx)

        # ctx = run_stage(stage10_ml.run,            ctx, 'stage_10',   ui)
        # ctx = run_stage(stage11_mitre.run,         ctx, 'stage_11',   ui)

        # ctx = run_stage(stage12_aggregation.run,   ctx, 'stage_12',   ui)
        # ui.show_stage12_detail(ctx)

        ctx = run_stage(stage13_quality.run,       ctx, 'stage_13',   ui)
        ui.show_stage13_detail(ctx)

        # ── Snapshot speichern (für späteren Reexport) ────────────────────────
        # try/except: Snapshot-Fehler darf Stage 14 NICHT blockieren
        try:
            save_ctx_snapshot(ctx, ctx.case_dir)
        except Exception as e:
            log.warning(f'  Snapshot konnte nicht gespeichert werden: {e} — Stage 14 läuft trotzdem')

        ctx = run_stage(stage14_export.run,        ctx, 'stage_14',   ui)
        ui.show_stage14_detail(ctx)

    finally:
        ui.stop()

    # ── Abschluss-Zusammenfassung ─────────────────────────────────────────────
    ui.show_summary(ctx)

    return 0 if not ctx.stage_errors else 1


# ── MULTI-IMAGE-ERKENNUNG (Ordner-Eingabe) ──────────────────────────────────

import re as _re

# Von der Pipeline unterstuetzte Image-Formate (vgl. utils/file_detection.py)
IMAGE_EXTENSIONS = {
    '.e01', '.ex01',                    # EnCase / EWF
    '.dd', '.raw', '.img',              # Raw
    '.vmdk',                            # VMware
    '.vhd', '.vhdx',                    # Hyper-V
    '.qcow2', '.qcow',                  # QEMU
    '.aff',                             # Advanced Forensic Format
}

# EWF-Folgesegmente: .E02-.E99, danach .EAA-.EZZ (auch .Ex..-Schreibweise).
# WICHTIG: Segmente sind KEINE eigenen Images — sie gehoeren zum .E01.
_EWF_SEGMENT = _re.compile(r'^\.e(x?)(?!01$)([0-9a-z]{2})$', _re.IGNORECASE)


def _scan_image_folder(folder: Path) -> list:
    """Findet Disk-Images in einem Ordner.

    EWF-Segmentdateien (disk.E02, disk.E03, ...) werden dem zugehoerigen
    disk.E01 zugeordnet (ein Beweisstueck, in Teilen gesichert) — eine
    Segmentdatei zaehlt nur, wenn das passende .E01 daneben liegt.

    Rueckgabe: [{'path': Path, 'size_gb': float, 'segments': int}, ...]
    """
    primaries: dict = {}     # stem(lower) -> Eintrag
    seg_candidates: list = []

    for f in sorted(folder.iterdir()):
        if not f.is_file():
            continue
        suf = f.suffix.lower()
        if suf in ('.e01', '.ex01'):
            primaries[f.stem.lower()] = {
                'path': f, 'size_bytes': f.stat().st_size, 'segments': 1}
        elif _EWF_SEGMENT.match(suf):
            seg_candidates.append(f)
        elif suf in IMAGE_EXTENSIONS:
            primaries[f.name.lower()] = {
                'path': f, 'size_bytes': f.stat().st_size, 'segments': 1}

    # Segmente nur zaehlen, wenn das passende .E01 existiert
    for f in seg_candidates:
        entry = primaries.get(f.stem.lower())
        if entry is not None and entry['path'].suffix.lower() in ('.e01', '.ex01'):
            entry['segments']   += 1
            entry['size_bytes'] += f.stat().st_size

    images = sorted(primaries.values(), key=lambda e: e['path'].name.lower())
    for e in images:
        e['size_gb'] = e.pop('size_bytes') / (1024 ** 3)
    return images


def _resolve_folder_input(folder: Path, case_mode: str = 'ask'):
    """Loest eine Ordner-Eingabe auf.

    1 Image (auch segmentiert)  -> Path (laeuft durch wie Datei-Angabe)
    mehrere Images + case_mode:
        'select' / interaktiv Nummer -> Path
        'batch'  / interaktiv [a]    -> list[Path] (getrennte Faelle)
    0 Images -> Abbruch mit Fehlermeldung.
    """
    images = _scan_image_folder(folder)

    if not images:
        print()
        print(f'  [Fehler] Keine Disk-Images in unterstuetzten Formaten gefunden: {folder}')
        print(f'  Unterstuetzt: {", ".join(sorted(IMAGE_EXTENSIONS))}')
        sys.exit(1)

    if len(images) == 1:
        e = images[0]
        seg = f' ({e["segments"]} Segmente)' if e['segments'] > 1 else ''
        print(f'  Ordner-Eingabe: 1 Image erkannt — {e["path"].name}'
              f' ({e["size_gb"]:.1f} GB){seg} — starte direkt.')
        return e['path']

    # ── Mehrere Images: Auswahl noetig ───────────────────────────────────
    if case_mode == 'batch':
        return [e['path'] for e in images]

    print()
    print('  ╔══════════════════════════════════════════════════════════════╗')
    print(f'  ║  Im angegebenen Pfad wurden {len(images)} Disk-Images erkannt:'.ljust(67) + '║')
    print('  ╠══════════════════════════════════════════════════════════════╣')
    for i, e in enumerate(images, 1):
        seg = f', {e["segments"]} Segmente' if e['segments'] > 1 else ''
        zeile = f'  ║   [{i}] {e["path"].name}  ({e["size_gb"]:.1f} GB{seg})'
        print(zeile.ljust(67) + '║')
    print('  ╠══════════════════════════════════════════════════════════════╣')
    print('  ╠══════════════════════════════════════════════════════════════╣')
    print('  ║  Gehoeren diese Images zum SELBEN Fall?                       ║')
    print('  ║  [j]      JA — gemeinsamer Durchlauf, EIN Report (Fall-Modus) ║')
    print('  ║  [Nummer] NEIN — nur dieses eine Image analysieren           ║')
    print('  ║  [a]      NEIN — alle nacheinander als getrennte Faelle      ║')
    print('  ║  [q]      abbrechen                                          ║')
    print('  ╚══════════════════════════════════════════════════════════════╝')
    print()

    if case_mode == 'combined':
        return {'combined': True, 'images': [e['path'] for e in images]}
    if case_mode == 'select':
        prompt = f'  Image auswaehlen [1-{len(images)}]: '
    elif case_mode == 'batch':
        return [e['path'] for e in images]
    else:
        prompt = f'  Auswahl [j / 1-{len(images)} / a / q]: '

    while True:
        raw = input(prompt).strip().lower()
        if raw == 'q':
            sys.exit(0)
        if raw == 'j':
            return {'combined': True, 'images': [e['path'] for e in images]}
        if raw == 'a':
            return [e['path'] for e in images]
        if raw.isdigit() and 1 <= int(raw) <= len(images):
            return images[int(raw) - 1]['path']
        print('  Bitte gueltige Eingabe.')


# ── STARTUP-MENÜ (immer angezeigt) ───────────────────────────────────────────

def _show_startup_menu(output_dir: Path, image: str) -> str:
    """
    Wird immer beim Start angezeigt — egal ob Image angegeben oder nicht.
    Gibt 'new' oder 'reexport' zurück.
    """
    image_label = image if image else '(kein Image angegeben)'
    print()
    print('╔══════════════════════════════════════════════════════════╗')
    print('║               DFIR Pipeline v3.0                        ║')
    print('╠══════════════════════════════════════════════════════════╣')
    print(f'║  [1]  Neuer Testlauf   {image_label[:34]:<34}║')
    print('║  [2]  Dokumente neu erstellen aus bestehendem Testlauf   ║')
    print('╚══════════════════════════════════════════════════════════╝')
    print()

    while True:
        choice = input('  Auswahl [1/2]: ').strip()
        if choice == '1':
            return 'new'
        if choice == '2':
            return 'reexport'
        print('  Bitte 1 oder 2 eingeben.')


def _run_reexport_flow(output_dir: Path) -> int:
    """Reexport-Logik: Testlauf auswählen → Stage 14 neu ausführen."""
    runs = list_available_runs(output_dir)

    if not runs:
        print()
        print('  ⚠  Du hast noch keinen Testlauf gestartet.')
        print('     Starte zuerst einen vollständigen Durchlauf:')
        print('     python pipeline.py <image>')
        print()
        return 1

    print()
    print('  Verfügbare Testläufe:')
    print()
    print(f'  {"Nr":>3}  {"Name":<45}  {"Erstellt":<19}  {"OS":<22}  {"Findings":>8}  {"IOCs":>6}')
    print('  ' + '─' * 110)
    for i, run in enumerate(runs, 1):
        print(f'  {i:>3}  {run["name"]:<45}  {run["created"]:<19}  '
              f'{run["os"][:22]:<22}  {run["findings"]:>8}  {run["iocs"]:>6}')
    print()

    while True:
        sel = input(f'  Testlauf auswählen [1–{len(runs)}]: ').strip()
        if sel.isdigit() and 1 <= int(sel) <= len(runs):
            selected = runs[int(sel) - 1]
            break
        print(f'  Bitte eine Zahl zwischen 1 und {len(runs)} eingeben.')

    print()
    print(f'  Gewählt: {selected["name"]}')
    print(f'  Erstelle neuen Ordner und generiere Dokumente neu ...')
    print()

    # Neuen Ordner erstellen (ohne Stage-14-Dokumente)
    new_case_dir = create_reexport_dir(selected['dir'], output_dir)

    # ctx aus Snapshot laden
    snapshot_path = selected['dir'] / 'ctx_snapshot.json'
    ctx           = reconstruct_ctx(snapshot_path, new_case_dir)

    # Stage 14 ausführen
    ui = PipelineUI(image_name=selected['name'])
    ui.start()
    try:
        ctx = run_stage(stage14_export.run, ctx, 'stage_14', ui)
        ui.show_stage14_detail(ctx)
    finally:
        ui.stop()

    print()
    print(f'  ✅  Dokumente erstellt in:')
    print(f'      {new_case_dir}')
    print()

    return 0 if not ctx.stage_errors else 1


if __name__ == '__main__':
    sys.exit(main())
