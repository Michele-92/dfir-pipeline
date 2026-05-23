import csv
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.pipeline_context import PipelineContext
from stages.stage13_quality import evaluate_quality

try:
    from ki_text_generator import generate_all_critical_texts
    from report_builder import build_critical_report
    _KI_AVAILABLE = True
except ImportError:
    _KI_AVAILABLE = False

log = logging.getLogger(__name__)

# ── Farben (HEX → RGB tuple) ─────────────────────────────────────────────────
C_DARK_BLUE  = (0x1F/255, 0x4E/255, 0x79/255)
C_MID_BLUE   = (0x2E/255, 0x75/255, 0xB6/255)
C_LIGHT_BLUE = (0xD5/255, 0xE8/255, 0xF0/255)
C_DARK_GREY  = (0x40/255, 0x40/255, 0x40/255)
C_MID_GREY   = (0x59/255, 0x59/255, 0x59/255)
C_LIGHT_GREY = (0xF2/255, 0xF2/255, 0xF2/255)
C_WHITE      = (1, 1, 1)
C_GREEN      = (0x37/255, 0x56/255, 0x23/255)
C_GREEN_L    = (0xE2/255, 0xEF/255, 0xDA/255)
C_ORANGE     = (0x84/255, 0x3C/255, 0x0C/255)
C_ORANGE_L   = (0xFC/255, 0xE4/255, 0xD6/255)
C_RED        = (0xC0/255, 0x00/255, 0x00/255)
C_RED_L      = (0xFF/255, 0xCC/255, 0xCC/255)
C_YELLOW_L   = (0xFF/255, 0xEB/255, 0x9C/255)


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 14: Export & Archivierung')
    case_dir = ctx.case_dir
    if not case_dir:
        log.error('Kein Case-Verzeichnis — Export übersprungen')
        return ctx

    _write_pipeline_report(ctx, case_dir)
    _write_autopsy_status(ctx, case_dir)
    _write_iocs_json(ctx, case_dir)
    _write_antiforensics_json(ctx, case_dir)
    _write_activity_csv(ctx, case_dir)
    _export_mactime_package(ctx, case_dir)
    _generate_report_pdf(ctx, case_dir)
    _generate_coc_pdf(ctx, case_dir)
    _generate_critical_report(ctx, case_dir)
    _upload_timesketch(ctx, case_dir)

    log.info(f'  Export abgeschlossen → {case_dir}')
    if ctx.coc:
        ctx.coc.add_entry('stage_14', 'Export abgeschlossen')
    return ctx


def _generate_critical_report(ctx: PipelineContext, case_dir: Path) -> None:
    if not _KI_AVAILABLE:
        log.warning('  DFIR Critical Report übersprungen — ki_text_generator/report_builder nicht verfügbar')
        return
    critical = [f for f in ctx.forensic_findings if f.severity == 'CRITICAL']
    if not critical:
        log.info('  DFIR Critical Report übersprungen — keine CRITICAL-Befunde')
        return
    try:
        log.info(f'  Generiere KI-Texte für {len(critical)} CRITICAL-Befunde...')
        ki_texte_map = generate_all_critical_texts(
            findings       = ctx.forensic_findings,
            delay_seconds  = 0.3,
        )
        out = case_dir / 'DFIR_Critical_Report.pdf'
        build_critical_report(
            findings     = ctx.forensic_findings,
            ki_texte_map = ki_texte_map,
            ctx          = ctx,
            output_path  = out,
        )
        log.info(f'  DFIR_Critical_Report.pdf → {out}')
    except Exception as e:
        log.warning(f'  DFIR Critical Report Fehler: {e}')


# ── pipeline_report.json ─────────────────────────────────────────────────────

def _write_pipeline_report(ctx: PipelineContext, case_dir: Path) -> None:
    duration = (datetime.now() - ctx.start_time).seconds // 60
    report   = {
        'meta': {
            'case_id':          case_dir.name,
            'created':          datetime.utcnow().isoformat() + 'Z',
            'pipeline_version': '3.0',
            'duration_minutes': duration,
        },
        'input': {
            'disk_image': str(ctx.disk_image_path),
            'ram_dump':   str(ctx.ram_dump_path) if ctx.ram_dump_path else None,
            'sha256':     ctx.sha256,
            'md5':        ctx.md5,
            'size_gb':    round(ctx.file_size_gb, 2),
            'file_type':  ctx.file_type,
        },
        'system_profile': {
            'os_family':  ctx.os_family,
            'os_name':    ctx.os_name,
            'kernel':     ctx.kernel_version,
            'hostname':   ctx.hostname,
            'timezone':   ctx.timezone,
        },
        'statistics': {
            'total_log_lines':    ctx.total_log_lines,
            'parsed_events':      ctx.parsed_events,
            'anomalies_found':    len(ctx.anomalies),
            'iocs_found':         len(ctx.iocs),
            'mitre_techniques':   len(ctx.mitre_hits),
            'antiforensics_hits': len(ctx.antiforensics_hits),
        },
        'iocs': [
            {'type': ioc.type, 'value': ioc.value, 'source': ioc.source}
            for ioc in ctx.iocs[:100]
        ],
        'mitre_hits': ctx.mitre_hits,
        'antiforensics': ctx.antiforensics_hits,
        'stage_status': ctx.stage_status,
        'quality': evaluate_quality(ctx),
        'ioc_quality': ctx.ioc_quality,
    }
    out = case_dir / 'pipeline_report.json'
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    log.info(f'  pipeline_report.json → {out}')


def _write_autopsy_status(ctx: PipelineContext, case_dir: Path) -> None:
    status = {
        'ran':    ctx.autopsy_ran,
        'reason': ctx.autopsy_reason,
        'results_count': len(ctx.autopsy_results.get('files', [])),
    }
    out = case_dir / 'autopsy_status.json'
    out.write_text(json.dumps(status, indent=2), encoding='utf-8')


def _write_iocs_json(ctx: PipelineContext, case_dir: Path) -> None:
    data = [
        {
            'type':       ioc.type,
            'value':      ioc.value,
            'source':     ioc.source,
            'timestamp':  ioc.timestamp.isoformat() if ioc.timestamp else None,
            'context':    ioc.context,
        }
        for ioc in ctx.iocs
    ]
    out = case_dir / 'iocs.json'
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    log.info(f'  iocs.json → {out}')


def _write_antiforensics_json(ctx: PipelineContext, case_dir: Path) -> None:
    out = case_dir / 'antiforensics.json'
    out.write_text(
        json.dumps(ctx.antiforensics_hits, indent=2, ensure_ascii=False, default=str),
        encoding='utf-8'
    )
    log.info(f'  antiforensics.json → {out}')


# ── Activity CSV (Logins, Reboots, Crashes) ──────────────────────────────────

# Schicht 1: Strukturierte Event-Types aus Parsern (primär, zuverlässig)
_REBOOT_EVENT_TYPES = {'boot', 'system_boot', 'reboot', 'shutdown', 'system_shutdown',
                       'service_start', 'kernel_start'}
_LOGIN_EVENT_TYPES  = {'ssh_login_success', 'ssh_login_fail', 'ssh_invalid_user',
                       'sudo_command', 'user_login', 'console_login', 'su_session',
                       'pam_session', 'auth_success', 'auth_failure'}
_CRASH_EVENT_TYPES  = {'kernel_panic', 'oom_kill', 'segfault', 'service_crash',
                       'kernel_error', 'oom_killer'}

# Schicht 2: Keyword-Fallback für generische Events (nur HIGH/CRITICAL)
_REBOOT_KEYWORDS = ['system boot', 'kernel command line', 'reached target basic system',
                    'systemd: starting', 'reboot', 'shutdown']
_LOGIN_KEYWORDS  = ['session opened', 'accepted password', 'accepted publickey',
                    'new session', 'logged in']
_CRASH_KEYWORDS  = ['kernel panic', 'oom killer', 'segfault', 'out of memory',
                    'killed process', 'call trace']


def _classify_event(event) -> Optional[str]:
    """Klassifiziert Event als REBOOT/LOGIN/CRASH — strukturiert zuerst, Keyword-Fallback."""
    et = (event.event_type or '').lower()
    if et in _REBOOT_EVENT_TYPES: return 'REBOOT'
    if et in _LOGIN_EVENT_TYPES:  return 'LOGIN'
    if et in _CRASH_EVENT_TYPES:  return 'CRASH'
    # Keyword-Fallback nur für HIGH/CRITICAL Events
    if getattr(event, 'severity', '') in ('high', 'critical', 'error'):
        msg = event.message.lower()
        if any(kw in msg for kw in _CRASH_KEYWORDS):  return 'CRASH'
        if any(kw in msg for kw in _REBOOT_KEYWORDS): return 'REBOOT'
    # Keyword-Fallback für alle Severity bei Login/Reboot
    msg = event.message.lower()
    if any(kw in msg for kw in _LOGIN_KEYWORDS):  return 'LOGIN'
    if any(kw in msg for kw in _REBOOT_KEYWORDS): return 'REBOOT'
    return None


def _write_activity_csv(ctx: PipelineContext, case_dir: Path) -> None:
    """Exportiert Logins, Reboots und Crashes — kombiniert + 3 separate CSVs."""
    if not ctx.events_db_path or not ctx.events_db_path.exists():
        log.warning('  activity CSVs: keine events.db vorhanden')
        return
    from utils.event_store import EventStore
    relevant = []
    with EventStore(ctx.events_db_path) as store:
        for event in store.iter_events():
            classified = _classify_event(event)
            if classified:
                relevant.append((event, classified))

    relevant.sort(key=lambda x: x[0].timestamp)

    # Kombinierte Timeline
    out = case_dir / 'activity_timeline.csv'
    with open(out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp_UTC', 'Event_Type', 'User', 'IP', 'Source', 'Details'])
        for event, et in relevant:
            writer.writerow([event.timestamp.isoformat(), et,
                             event.user or '', event.ip or '',
                             event.source, event.message[:300]])

    # 3 separate CSVs
    _write_event_csvs(relevant, case_dir)
    log.info(f'  activity_timeline.csv + 3 separate CSVs → {case_dir}  ({len(relevant)} Einträge)')


def _write_event_csvs(relevant: list, case_dir: Path) -> None:
    """Schreibt system_reboots.csv, login_events.csv, system_crashes.csv."""
    configs = {
        'REBOOT': ('system_reboots.csv',
                   ['Timestamp_UTC', 'Source', 'Details']),
        'LOGIN':  ('login_events.csv',
                   ['Timestamp_UTC', 'User', 'IP', 'Method', 'Source', 'Details']),
        'CRASH':  ('system_crashes.csv',
                   ['Timestamp_UTC', 'Severity', 'Source', 'Details']),
    }
    handles = {}
    writers = {}
    for et, (fname, header) in configs.items():
        f = open(case_dir / fname, 'w', newline='', encoding='utf-8')
        handles[et] = f
        writers[et] = csv.writer(f)
        writers[et].writerow(header)

    for event, et in relevant:
        if et == 'REBOOT':
            writers['REBOOT'].writerow([event.timestamp.isoformat(),
                                        event.source, event.message[:200]])
        elif et == 'LOGIN':
            method = event.event_type or ''
            writers['LOGIN'].writerow([event.timestamp.isoformat(),
                                       event.user or '', event.ip or '',
                                       method, event.source, event.message[:200]])
        elif et == 'CRASH':
            sev = getattr(event, 'severity', '')
            writers['CRASH'].writerow([event.timestamp.isoformat(),
                                       sev, event.source, event.message[:200]])

    for f in handles.values():
        f.close()


# ── MACtime CSV-Paket ────────────────────────────────────────────────────────

def _export_mactime_package(ctx: PipelineContext, case_dir: Path) -> None:
    """Exportiert MACtime-Events aus DuckDB als standalone CSV-Paket."""
    if not ctx.events_db_path or not ctx.events_db_path.exists():
        return
    from utils.event_store import EventStore
    out = case_dir / 'filesystem_timeline.csv'
    count = 0
    with EventStore(ctx.events_db_path) as store:
        with open(out, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp_UTC', 'MACB_Type', 'File_Path', 'Severity', 'Message'])
            for event in store.iter_events():
                if event.source != 'mactime':
                    continue
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.file_path or '',
                    event.severity,
                    event.message[:300],
                ])
                count += 1
    log.info(f'  filesystem_timeline.csv → {out}  ({count:,} MACtime-Events)')


# ── PDF Report ───────────────────────────────────────────────────────────────

def _generate_report_pdf(ctx: PipelineContext, case_dir: Path) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, PageBreak)
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        log.warning('reportlab nicht installiert — PDF-Export übersprungen')
        return

    out_file = case_dir / 'report.pdf'
    doc = SimpleDocTemplate(str(out_file), pagesize=A4,
                            leftMargin=15*mm, rightMargin=15*mm,
                            topMargin=35*mm, bottomMargin=22*mm)

    styles    = getSampleStyleSheet()
    story     = []
    case_id   = case_dir.name
    created   = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    quality   = evaluate_quality(ctx)
    duration  = (datetime.now() - ctx.start_time).seconds // 60

    def _rl_color(t):
        from reportlab.lib.colors import Color
        return Color(*t)

    def _h1(text):
        return Paragraph(f'<font color="#{_hex(C_DARK_BLUE)}" size="14"><b>{text}</b></font>',
                         styles['Normal'])

    def _h2(text):
        return Paragraph(f'<font color="#{_hex(C_MID_BLUE)}" size="11"><b>{text}</b></font>',
                         styles['Normal'])

    def _body(text):
        return Paragraph(f'<font size="9" color="#{_hex(C_DARK_GREY)}">{text}</font>',
                         styles['Normal'])

    def _spacer(h=4):
        return Spacer(1, h*mm)

    def _table(data, col_widths=None, header=True):
        from reportlab.platypus import Table, TableStyle
        from reportlab.lib.colors import Color, white, HexColor
        t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
        style = [
            ('BACKGROUND', (0,0), (-1,0), _rl_color(C_DARK_BLUE)),
            ('TEXTCOLOR',  (0,0), (-1,0), _rl_color(C_WHITE)),
            ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,-1), 8),
            ('FONTNAME',   (0,1), (-1,-1), 'Helvetica'),
            ('TEXTCOLOR',  (0,1), (-1,-1), _rl_color(C_DARK_GREY)),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),
             [_rl_color(C_WHITE), _rl_color(C_LIGHT_GREY)]),
            ('GRID', (0,0), (-1,-1), 0.3, _rl_color((0xDD/255,)*3)),
            ('LEFTPADDING',  (0,0), (-1,-1), 5),
            ('RIGHTPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING',   (0,0), (-1,-1), 4),
            ('BOTTOMPADDING',(0,0), (-1,-1), 4),
        ]
        t.setStyle(TableStyle(style))
        return t

    W = A4[0] - 30*mm  # Nutzbare Breite

    # ── Seite 1: Deckblatt ───────────────────────────────────────────────────
    story.append(_spacer(5))
    story.append(_banner('DFIR ANALYSE-REPORT', C_DARK_BLUE, C_WHITE, 28, W))
    story.append(_spacer(2))
    story.append(_body('Automatisch generierter forensischer Analysebericht'))
    story.append(_spacer(8))

    kv1 = [
        ['Case-ID',    case_id],       ['Erstellt',    created],
        ['Dauer',      f'{duration} Minuten'], ['Format', ctx.file_type],
        ['SHA256',     ctx.sha256[:32]+'...'],  ['MD5',   ctx.md5],
        ['Qualitaet',  quality],       ['IOC-Qualitaet', ctx.ioc_quality],
    ]
    story.append(_h2('Case-Informationen'))
    story.append(_spacer(2))
    story.append(_kv_table(kv1, W, _rl_color))
    story.append(_spacer(6))

    kv2 = [
        ['OS',           ctx.os_name or '-'],
        ['Kernel',       ctx.kernel_version or '-'],
        ['Hostname',     ctx.hostname or '-'],
        ['Zeitzone',     ctx.timezone],
        ['Autopsy',      'Gelaufen' if ctx.autopsy_ran else ctx.autopsy_reason[:60]],
        ['TSK-Fallback', 'Aktiv' if ctx.tsk_fallback_used else 'Nicht noetig'],
    ]
    story.append(_h2('System-Information'))
    story.append(_spacer(2))
    story.append(_kv_table(kv2, W, _rl_color))
    story.append(PageBreak())

    # ── Seite 2: Executive Summary ───────────────────────────────────────────
    story.append(_h1('Executive Summary'))
    story.append(_spacer(4))
    stats = [
        (f'{ctx.total_log_lines:,}',          'Log-Zeilen'),
        (f'{ctx.parsed_events:,}',             'Events'),
        (str(len(ctx.iocs)),                   'IOCs'),
        (str(len(ctx.antiforensics_hits)),     'Anti-Forensics'),
        (str(len(ctx.anomalies)),              'ML-Anomalien'),
    ]
    story.append(_stat_boxes(stats, W, _rl_color))
    story.append(_spacer(6))

    critical   = [e for e in ctx.normalized_events if e.severity == 'critical']
    high       = [e for e in ctx.normalized_events if e.severity == 'high']
    top_events = (critical + high)[:10]
    if top_events:
        story.append(_h2('Kritische Funde'))
        story.append(_spacer(2))
        rows = [['Schwere', 'Zeitstempel', 'Beschreibung', 'Quelle']]
        for e in top_events:
            rows.append([
                e.severity.upper(),
                e.timestamp.strftime('%Y-%m-%d %H:%M'),
                e.message[:85],
                e.source[:20],
            ])
        story.append(_table(rows, [25*mm, 35*mm, 90*mm, 20*mm]))
        story.append(_spacer(4))

    # Sofortmassnahmen — nur auf tatsaechlich vorhandenen Daten basierend
    # (MITRE-Empfehlungen auskommentiert: stage11_mitre nicht aktiv)
    recs = []
    if ctx.antiforensics_hits:
        recs.append('Beweise sichern — Anti-Forensik-Techniken erkannt (Details: Seite 4)')
    critical_af = [h for h in ctx.antiforensics_hits if h.get('severity') == 'critical']
    if critical_af:
        recs.append(f'{len(critical_af)} KRITISCHE Anti-Forensik-Befunde — sofortige Pruefung erforderlich')
    if ctx.tsk_fallback_used:
        recs.append('IOC-Qualitaet MITTEL — manuelle Nachpruefung empfohlen')
    if recs:
        story.append(_h2('Sofortmassnahmen'))
        story.append(_spacer(2))
        for i, r in enumerate(recs, 1):
            story.append(_body(f'{i}. {r}'))

    # ── AUSKOMMENTIERT: MITRE-Sofortmassnahmen (stage11_mitre nicht aktiv) ───
    # ctx.mitre_hits ist immer leer solange Stage 11 auskommentiert ist.
    # Zum Reaktivieren: if False: Block entfernen + stage11_mitre einkommentieren.
    if False:
        if any(h['technique_id'].startswith('T1003') for h in ctx.mitre_hits):
            recs.append('Alle Passwoerter sofort aendern (Credential Dumping erkannt)')
        if any(h['technique_id'] == 'T1098' for h in ctx.mitre_hits):
            recs.append('Neue Benutzerkonten ueberpruefen und ggf. deaktivieren')
    story.append(PageBreak())

    # ── AUSKOMMENTIERT: Alt Seite 3 — Forensische Befunde (Stage 8.5) ────────
    # stage_timeline_analysis ist in pipeline.py auskommentiert.
    # ctx.forensic_findings ist daher immer leer.
    # Reaktivieren: if False entfernen + stage_timeline_analysis einkommentieren.
    if False:
        story.append(_h1('Forensische Befunde'))
        story.append(_spacer(3))
        story.append(_body(
            'Automatisch erkannte Anomalien basierend auf MACtime-Timestamps, '
            'Anti-Forensics-Indikatoren und CVE-Zeitfenstern.'
        ))
        story.append(_spacer(4))
        if ctx.forensic_findings:
            rows = [['Schwere', 'Regel', 'Datei', 'Beschreibung']]
            for f in ctx.forensic_findings[:30]:
                rows.append([f.severity, f.rule[:25], f.file[:40], f.description[:80]])
            story.append(_table(rows, [20*mm, 35*mm, 45*mm, 70*mm]))
            story.append(_spacer(4))
            story.append(_body('Vollstaendige Befunde: forensic_findings.json'))
        else:
            story.append(_body('Keine forensischen Befunde erkannt.'))
        story.append(PageBreak())

    # ── Seite 3: Forensische Timeline ────────────────────────────────────────
    story.append(_h1('Forensische Timeline'))
    story.append(_spacer(3))
    story.append(_body(
        'Alle Zeitstempel sind in UTC. Angezeigt: kritische / hohe / mittlere Ereignisse '
        'chronologisch (max. 50). Vollstaendige Timeline: activity_timeline.csv'
    ))
    story.append(_spacer(4))
    timeline_events = sorted(
        [e for e in ctx.normalized_events if e.severity in ('critical', 'high', 'medium')],
        key=lambda e: e.timestamp
    )[:50]
    if timeline_events:
        rows = [['Zeitstempel (UTC)', 'Ereignis', 'Quelle', 'Schwere']]
        for e in timeline_events:
            rows.append([
                e.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                e.message[:80],
                e.source[:20],
                e.severity.upper(),
            ])
        story.append(_table(rows, [42*mm, 90*mm, 22*mm, 16*mm]))
    else:
        story.append(_body('Keine relevanten Timeline-Events.'))
    story.append(_spacer(5))
    ts_url = 'http://localhost:5000/sketch/1/explore'
    ts_box = Table([[Paragraph(
        f'<font color="#{_hex(C_MID_BLUE)}"><b>Interaktive Timeline (Timesketch)</b></font>'
        f'<br/><font size="9">{ts_url}</font>',
        _normal_style()
    )]], colWidths=[W])
    ts_box.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), _rl_color_from_tuple(C_LIGHT_BLUE)),
        ('BOX',           (0, 0), (-1, -1), 1.5, _rl_color_from_tuple(C_MID_BLUE)),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
    ]))
    story.append(ts_box)
    story.append(PageBreak())

    # ── Seite 4: Anti-Forensics Befundbericht (Betreuer-Template-Format) ─────
    story.append(_h1('Anti-Forensics — Befundbericht'))
    story.append(_spacer(3))
    story.append(_body(
        'Die folgenden Befunde basieren auf forensischer Analyse des Disk-Images via '
        'TSK/icat ohne Mounting (forensisch unveraendert). Jeder Abschnitt enthaelt '
        'eine technische Einordnung (Zusammenspiel) und den konkreten Befund.'
    ))
    story.append(_spacer(5))

    # Hilfsfunktionen fuer Befund-Boxen im Betreuer-Template-Format
    def _befund_pos(text):
        """Rote Box: Positiv-Befund (verdaechtig / Anti-Forensik-Indikator gefunden)."""
        b = Table([[Paragraph(
            f'<font size="8" color="#{_hex(C_RED)}"><b>Befund (Positiv):</b></font> '
            f'<font size="8" color="#{_hex(C_DARK_GREY)}">{text}</font>',
            _normal_style_left()
        )]], colWidths=[W])
        b.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), _rl_color_from_tuple(C_RED_L)),
            ('BOX',           (0, 0), (-1, -1), 1.0, _rl_color_from_tuple(C_RED)),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        return b

    def _befund_neg(text):
        """Gruene Box: Negativ-Befund (sauber / kein Indikator gefunden)."""
        b = Table([[Paragraph(
            f'<font size="8" color="#{_hex(C_GREEN)}"><b>Befund (Negativ):</b></font> '
            f'<font size="8" color="#{_hex(C_DARK_GREY)}">{text}</font>',
            _normal_style_left()
        )]], colWidths=[W])
        b.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), _rl_color_from_tuple(C_GREEN_L)),
            ('BOX',           (0, 0), (-1, -1), 1.0, _rl_color_from_tuple(C_GREEN)),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        return b

    def _ref(text):
        return _body(f'<i>Ref.: {text}</i>')

    def _zsp(text):
        return _body(f'<b>Zusammenspiel:</b> {text}')

    grub    = getattr(ctx, 'grub_config', {})
    symlinks = getattr(ctx, 'primary_symlinks', {})

    # ── Log-Manipulation ─────────────────────────────────────────────────────
    story.append(_h2('Log-Manipulation'))
    story.append(_spacer(2))

    devnull_hits  = [h for h in ctx.antiforensics_hits if h.get('type') == 'devnull_symlink']
    devnull_paths = [p for p, t in symlinks.items() if '/dev/null' in t]
    if devnull_hits:
        paths_str = ', '.join(devnull_paths[:5])
        story.append(_befund_pos(
            f'Die folgenden Log-Dateien bzw. Shell-Histories sind via Symlink auf /dev/null '
            f'gesetzt: {paths_str}. Somit werden keinerlei Protokolle geschrieben.'
        ))
    else:
        story.append(_befund_neg(
            'Es wurden keine relevanten Log-Dateien oder Shell-Histories via Symlink auf '
            '/dev/null gesetzt. Die Protokollierung ist nicht auf diesem Wege unterbunden.'
        ))
    story.append(_spacer(2))

    wtmp_hits = [h for h in ctx.antiforensics_hits if h.get('type') == 'journal_wtmp_mismatch']
    if wtmp_hits:
        story.append(_befund_pos(wtmp_hits[0].get('details', '')[:300]))
    else:
        story.append(_befund_neg(
            'Die Login-Ereignisse aus wtmp und dem systemd-Journal stimmen ueberein. '
            'Es liegen keine Anzeichen fuer nachtraegliche Log-Manipulation vor.'
        ))
    story.append(_spacer(3))

    # ── rc.local ─────────────────────────────────────────────────────────────
    story.append(_h2('Automatische Aktionen beim Systemstart (rc.local / local.d)'))
    story.append(_spacer(2))
    rc_hits = [h for h in ctx.antiforensics_hits if h.get('type') == 'rc_local_antiforensics']
    if rc_hits:
        details_str = '; '.join(h.get('details', '')[:80] for h in rc_hits[:3])
        story.append(_befund_pos(
            f'In der Startkonfiguration wurden Anti-Forensik-Kommandos identifiziert: '
            f'{details_str}.'
        ))
    else:
        story.append(_befund_neg(
            'Es wurden keine Anti-Forensik-Kommandos (Log-Loeschung, /dev/null-Verlinkung, '
            'Service-Stopp) in der Systemstartdatei festgestellt.'
        ))
    story.append(_spacer(2))
    story.append(_ref('/etc/rc.local, /etc/rc.d/rc.local, /etc/local.d/*.start'))
    story.append(_spacer(4))

    # ── 1. GRUB Bootloader Konfiguration ─────────────────────────────────────
    story.append(_h2('1. GRUB Bootloader Konfiguration (Boot-Parameter)'))
    story.append(_spacer(2))
    story.append(_zsp(
        'Der Bootloader uebergibt beim Systemstart Parameter an den Kernel, welche das '
        'Speichermanagement priorisiert steuern (z.B. sofortiges Nullen freigegebener Pages '
        'via init_on_free), noch bevor einkompilierte Standardwerte greifen.'
    ))
    story.append(_spacer(2))
    grub_af     = grub.get('antiforensic_params', [])
    grub_hits   = [h for h in ctx.antiforensics_hits if h.get('type') == 'grub_memory_wipe']
    if grub_hits:
        params_str = ', '.join(grub_af) if grub_af else 'init_on_free / page_poison'
        story.append(_befund_pos(
            f'Im Rahmen der Auswertung wurden Boot-Parameter festgestellt, die eine '
            f'sofortige Bereinigung freigegebener Speicherseiten erzwingen '
            f'(Parameter: {params_str}). Dies erschwert die post-mortem Rekonstruktion '
            f'volatiler Daten aus Speicherdumps erheblich.'
        ))
    else:
        story.append(_befund_neg(
            'Es wurden keine dynamischen Boot-Parameter zur aktiven Bereinigung des '
            'Arbeitsspeichers (z.B. init_on_free, page_poison) festgestellt.'
        ))
    sources = grub.get('sources', [])
    story.append(_spacer(2))
    story.append(_ref(', '.join(sources) if sources
                     else '/etc/default/grub, /boot/grub/grub.cfg, /boot/grub/grubenv'))
    story.append(_spacer(4))

    # ── 2. Hardcoded Kernel Konfigurationen ───────────────────────────────────
    story.append(_h2('2. Hardcoded Kernel Konfigurationen'))
    story.append(_spacer(2))
    story.append(_zsp(
        'Die statische Konfigurationsdatei spiegelt die Kompilierungs-Flags des Kernels '
        'wider. Fehlen dynamische GRUB-Parameter, definiert diese Basis '
        '(z.B. CONFIG_INIT_ON_FREE_DEFAULT_ON=y), ob das OS Speicherseiten nativ '
        'beim Freigeben ueberschreibt.'
    ))
    story.append(_spacer(2))
    flags_map   = getattr(ctx, 'kernel_compile_flags', {})
    flags_hits  = [h for h in ctx.antiforensics_hits if h.get('type') == 'kernel_compile_antiforensics']
    all_flags   = list(dict.fromkeys(
        f for info in flags_map.values() for f in info.get('active_flags', [])
    ))
    if flags_hits and all_flags:
        story.append(_befund_pos(
            f'Die Analyse der statischen Kernel-Konfiguration weist einkompilierte '
            f'Anti-Forensik-Flags auf: {", ".join(all_flags)}. '
            f'Der Kernel ueberschreibt Speicherbereiche nativ bei deren Freigabe.'
        ))
    else:
        story.append(_befund_neg(
            'Die einkompilierte Kernel-Konfiguration weist keine aktiven Memory-Wiping-Flags '
            'auf. Eine systemseitige, automatische Ueberschreibung des RAMs ist auf '
            'Kernel-Ebene nicht konfiguriert.'
        ))
    all_k = getattr(ctx, 'all_kernel_versions', []) or [ctx.kernel_version]
    story.append(_spacer(2))
    story.append(_ref(', '.join(f'/boot/config-{k}' for k in all_k[:3])))
    story.append(_spacer(4))

    # ── 3. Systemd Services (Userland Anti-Forensik) ─────────────────────────
    story.append(_h2('3. Systemd Services (Userland Anti-Forensik)'))
    story.append(_spacer(2))
    story.append(_zsp(
        'Systemd steuert den Lebenszyklus von Diensten. Ueber die ExecStop-Direktive '
        'koennen bei Terminierung eines Prozesses gezielt externe Userland-Tools '
        '(z.B. sdmem) aufgerufen werden, um den Applikationsspeicher zu wipen.'
    ))
    story.append(_spacer(2))
    execstop_hits = [h for h in ctx.antiforensics_hits if h.get('type') == 'execstop_wiping']
    if execstop_hits:
        story.append(_befund_pos(
            f'In der Dienstkonfiguration wurde eine gezielte Anti-Forensik-Routine '
            f'identifiziert. Beim Beenden des Dienstes wird ein Wiping-Tool via ExecStop '
            f'ausgefuehrt: {execstop_hits[0].get("details", "")[:180]}'
        ))
    else:
        story.append(_befund_neg(
            'Die Ueberpruefung der relevanten Service-Units ergab keine Aufrufe von '
            'externen Speicher-Wiping-Tools bei Prozessterminierungen. '
            'Verdaechtige ExecStop-Direktiven liegen nicht vor.'
        ))
    story.append(_spacer(2))
    story.append(_ref(
        '/etc/systemd/system/*.service, /lib/systemd/system/*.service, '
        '/usr/lib/systemd/system/*.service'
    ))
    story.append(_spacer(4))

    # ── 4. Swap Konfiguration ─────────────────────────────────────────────────
    story.append(_h2('4. Swap Konfiguration'))
    story.append(_spacer(2))
    story.append(_zsp(
        'Bei hohem RAM-Bedarf lagert der Kernel inaktive Speicherseiten auf einen '
        'persistenten Datentraeger aus (Swap). Diese Fragmente sind essenzielle Quellen '
        'fuer die Deadbox-Speicherforensik.'
    ))
    story.append(_spacer(2))
    swap = getattr(ctx, 'swap_config', {})
    if swap.get('found'):
        entries   = swap.get('entries', [])
        swap_info = ', '.join(f"{e.get('type','?')}: {e.get('path','?')}" for e in entries[:3])
        story.append(_befund_pos(
            f'Es wurde eine aktive Auslagerungskonfiguration ({swap_info}) festgestellt. '
            f'Diese stellt eine primaere Quelle fuer ausgelagerte volatile Artefakte dar.'
        ))
    else:
        story.append(_befund_neg(
            'Es ist weder eine Swap-Partition noch eine Swap-Datei konfiguriert. '
            'Das System lagert keine Speicherseiten auf den persistenten Datentraeger aus. '
            'Eine Deadbox-Speicherforensik ueber Swap-Artefakte ist nicht moeglich.'
        ))
    story.append(_spacer(2))
    story.append(_ref('/etc/fstab'))
    story.append(_spacer(4))

    # ── 5. Systemzustand (Kernel-Diskrepanz & Pending Reboot) ─────────────────
    story.append(_h2('5. Systemzustand (Kernel-Diskrepanz & Pending Reboot)'))
    story.append(_spacer(2))
    story.append(_zsp(
        'Paketmanager schreiben nach Kernel-Updates die grub.cfg neu. Der geladene Kernel '
        'aendert sich jedoch erst nach einem Reboot. Diskrepanzen zwischen Konfiguration '
        'und System-Logs belegen die Uptime auf einem Alt-Kernel.'
    ))
    story.append(_spacer(2))
    disc_hits      = [h for h in ctx.antiforensics_hits if h.get('type') == 'kernel_discrepancy']
    reboot_hits    = [h for h in ctx.antiforensics_hits if h.get('type') == 'pending_reboot']
    active_k       = grub.get('active_kernel', '')
    loaded_k       = getattr(ctx, 'loaded_kernel_from_logs', '')
    reboot_pending = getattr(ctx, 'reboot_pending', False)
    if disc_hits or reboot_hits:
        story.append(_befund_pos(
            f'Es liegt eine Diskrepanz zwischen dem konfigurierten Default-Kernel '
            f'({active_k or "unbekannt"}) und dem tatsaechlich geladenen Kernel '
            f'({loaded_k or "unbekannt"}) vor.'
            + (' Das Vorhandensein des Reboot-Flags belegt, dass das System seit dem '
               'Kernel-Update nicht neu gestartet wurde.'
               if reboot_pending else '')
        ))
    else:
        story.append(_befund_neg(
            f'Der in der GRUB-Konfiguration hinterlegte Default-Kernel '
            f'({active_k or ctx.kernel_version or "unbekannt"}) stimmt mit dem '
            f'ermittelten Systemstatus ueberein. Es liegen keine Artefakte vor, die auf '
            f'einen ausstehenden Neustart oder eine Laufzeitdiskrepanz hindeuten.'
        ))
    story.append(_spacer(2))
    story.append(_ref(
        '/boot/grub/grub.cfg, /var/run/reboot-required, /var/log/kern.log'
    ))
    story.append(PageBreak())

    # ── AUSKOMMENTIERT: Alt Seite 5 — Anti-Forensics Tabelle + ML ────────────
    # Ersetzt durch Seite 4 im Betreuer-Template-Format.
    # ML-Anomalien: stage10_ml auskommentiert — ctx.anomalies immer leer.
    # Reaktivieren: if False entfernen.
    if False:
        story.append(_h1('Anti-Forensics & ML-Anomalien'))
        story.append(_spacer(3))
        if ctx.antiforensics_hits:
            story.append(_body(f'Anti-Forensics: {len(ctx.antiforensics_hits)} Treffer'))
            rows = [['Technik', 'Datei / Quelle', 'Details', 'Schwere']]
            for h in ctx.antiforensics_hits[:20]:
                rows.append([h['type'], h['file'][:40], h['details'][:60], h['severity']])
            story.append(_table(rows, [35*mm, 45*mm, 70*mm, 20*mm]))
        story.append(_h2('ML-Anomalien (Isolation Forest)'))
        if ctx.anomalies:
            rows = [['Score', 'Zeitstempel', 'Event', 'Quelle']]
            for e in sorted(ctx.anomalies, key=lambda x: x.anomaly_score, reverse=True)[:20]:
                rows.append([f'{e.anomaly_score:.2f}',
                             e.timestamp.strftime('%Y-%m-%d %H:%M'),
                             e.message[:70], e.source[:20]])
            story.append(_table(rows, [18*mm, 35*mm, 95*mm, 22*mm]))
        else:
            story.append(_body('Keine Anomalien erkannt.'))
        story.append(PageBreak())

    # ── Seite 5: IOC-Liste ───────────────────────────────────────────────────
    story.append(_h1('Indicators of Compromise (IOCs)'))
    story.append(_spacer(3))
    story.append(_body(
        f'IOC-Qualitaet: {ctx.ioc_quality}  |  {len(ctx.iocs)} IOCs extrahiert  |  '
        f'Vollstaendige Liste: iocs.json'
    ))
    story.append(_spacer(4))

    ips     = [i for i in ctx.iocs if i.type in ('ip', 'ipv6')]
    domains = [i for i in ctx.iocs if i.type in ('domain', 'url')]
    hashes  = [i for i in ctx.iocs if i.type in ('hash_md5', 'hash_sha256')]
    others  = [i for i in ctx.iocs if i.type in ('email', 'cve', 'registry_key')]

    for group_name, group in [('IP-Adressen', ips), ('Domains / URLs', domains),
                               ('Datei-Hashes', hashes), ('Sonstige IOCs', others)]:
        if not group:
            continue
        story.append(_h2(group_name))
        story.append(_spacer(2))
        rows = [['Typ', 'Wert', 'Quelle']]
        for ioc in group[:30]:
            rows.append([ioc.type, ioc.value[:60], ioc.source[:20]])
        story.append(_table(rows, [25*mm, 117*mm, 28*mm]))
        story.append(_spacer(4))
    if not (ips or domains or hashes or others):
        story.append(_body('Keine IOCs extrahiert.'))

    story.append(PageBreak())

    # ── Seite 6: Nutzer-Profil & Netzwerk ────────────────────────────────────
    story.append(_h1('Nutzer-Profil & Netzwerk'))
    story.append(_spacer(3))
    primary_profile = next((p for p in ctx.partition_profiles if p.get('is_primary')), {})

    # Nutzer-Tabelle
    story.append(_h2('Nutzer-Uebersicht'))
    story.append(_spacer(2))
    users = ctx.users or primary_profile.get('users', [])
    display_users = [u for u in users if not u.get('is_system') or u.get('is_unexpected')]
    if display_users:
        rows = [['Name', 'UID', 'Shell', 'Login', 'Passwort', 'Sudo', 'Auffaellig']]
        for u in display_users[:15]:
            flag = ''
            if u.get('uid') == 0 and u.get('name') != 'root':
                flag = '! UID=0'
            elif u.get('is_unexpected'):
                flag = '! unbekannt'
            rows.append([
                u.get('name', ''),
                str(u.get('uid', '')),
                (u.get('shell', '') or '')[-20:],
                'Ja' if u.get('login_allowed') else 'Nein',
                'Ja' if u.get('has_password')  else 'Nein',
                'Ja' if u.get('has_sudo')       else '-',
                flag,
            ])
        story.append(_table(rows, [28*mm, 14*mm, 35*mm, 14*mm, 18*mm, 14*mm, 30*mm]))
    else:
        story.append(_body('Keine regulaeren Nutzer gefunden.'))
    story.append(_spacer(4))

    # SSH-Konfiguration
    ssh = primary_profile.get('ssh_config', {})
    if ssh:
        story.append(_h2('SSH-Konfiguration'))
        story.append(_spacer(2))
        ssh_rows = []
        if ssh.get('permit_root_login'):
            ssh_rows.append(['Root-Login', ssh['permit_root_login']])
        if ssh.get('password_auth'):
            ssh_rows.append(['Passwort-Authentifizierung', ssh['password_auth']])
        if ssh.get('port', '') not in ('22', ''):
            ssh_rows.append(['SSH-Port (nicht standard)', ssh['port']])
        if ssh.get('allow_users'):
            ssh_rows.append(['AllowUsers', ssh['allow_users']])
        if ssh.get('deny_users'):
            ssh_rows.append(['DenyUsers', ssh['deny_users']])
        if ssh_rows:
            story.append(_kv_table(ssh_rows, W, _rl_color))
        story.append(_spacer(4))

    # Netzwerk
    net = primary_profile.get('network', {})
    story.append(_h2('Netzwerk-Konfiguration'))
    story.append(_spacer(2))
    net_rows = []
    if ctx.ip_addresses:
        net_rows.append(['IP-Adressen', ', '.join(ctx.ip_addresses[:8])])
    if net.get('interfaces'):
        net_rows.append(['Interfaces', ', '.join(net['interfaces'][:6])])
    if net.get('gateway'):
        net_rows.append(['Gateway', net['gateway']])
    if net.get('dns_servers'):
        net_rows.append(['DNS-Server', ', '.join(net['dns_servers'][:4])])
    if net.get('mac_hints'):
        net_rows.append(['MAC-Hinweise', ', '.join(net['mac_hints'][:3]) + ' (aus DHCP/NM)'])
    if net_rows:
        story.append(_kv_table(net_rows, W, _rl_color))
    else:
        story.append(_body('Netzwerk-Daten nicht verfuegbar.'))
    story.append(PageBreak())

    # ── Seite 7: System-Profiling ─────────────────────────────────────────────
    story.append(_h1('System-Profiling'))
    story.append(_spacer(4))
    kv3 = [
        ['OS-Familie',      ctx.os_family or '-'],
        ['OS-Name',         ctx.os_name or '-'],
        ['Kernel (aktiv)',  ctx.kernel_version or '-'],
        ['Alle Kernel',     ', '.join(getattr(ctx, 'all_kernel_versions', [])) or '-'],
        ['Hostname',        ctx.hostname or '-'],
        ['Zeitzone',        ctx.timezone],
        ['Image-Format',    ctx.file_type],
        ['Image-Groesse',   f'{ctx.file_size_gb:.2f} GB'],
        ['SHA256',          ctx.sha256],
        ['MD5',             ctx.md5],
        ['Virtualisierung', primary_profile.get('virtualization', '-')],
    ]
    story.append(_kv_table(kv3, W, _rl_color))
    story.append(PageBreak())

    # ══ ANHANG ════════════════════════════════════════════════════════════════

    # ── Anhang A: Pipeline-Status & Qualitaet ─────────────────────────────────
    story.append(_banner('ANHANG', C_MID_GREY, C_WHITE, 14, W))
    story.append(_spacer(4))
    story.append(_h1('A — Pipeline-Status & Qualitaet'))
    story.append(_spacer(3))
    story.append(_body(f'Gesamtqualitaet: {quality}  |  Fehler: {len(ctx.stage_errors)}'))
    story.append(_spacer(3))
    stage_rows = [['Stufe', 'Status', 'Fehler / Anmerkung']]
    for stage_name, status in ctx.stage_status.items():
        err = ctx.stage_errors.get(stage_name, '')
        stage_rows.append([stage_name, status, err[:60]])
    story.append(_table(stage_rows, [35*mm, 40*mm, 95*mm]))
    story.append(PageBreak())

    # ── AUSKOMMENTIERT: Alt Seite 6 — Anti-Forensics Systemkonfiguration ─────
    # Tabellenbasierter Ansatz — ersetzt durch Seite 4 (Betreuer-Template-Format).
    # Reaktivieren: if False entfernen.
    if False:  # ── Alt Seite 6: Anti-Forensics Systemkonfiguration (tabellenbasiert) ──────────
        # Reaktivieren: if False entfernen
        story.append(_h1('Anti-Forensics — Systemkonfiguration'))
        story.append(_spacer(3))
        story.append(_body(
            'Systemkonfigurationsdaten die auf Anti-Forensik-Massnahmen hinweisen. '
            'Extrahiert via TSK/icat aus dem Disk-Image ohne Mounting (forensisch unveraendert).'
        ))
        story.append(_spacer(5))

        # ── GRUB-Konfiguration ────────────────────────────────────────────────────
        story.append(_h2('GRUB-Bootloader-Konfiguration'))
        story.append(_spacer(2))
        grub = getattr(ctx, 'grub_config', {})
        grub_rows = []
        if grub.get('active_kernel'):
            grub_rows.append(['Aktiver Kernel (GRUB-Default)', grub['active_kernel']])
        if grub.get('fallback_kernels'):
            grub_rows.append(['Fallback-Kernel', ', '.join(grub['fallback_kernels'])])
        if grub.get('grubenv_entry'):
            grub_rows.append(['grubenv saved_entry', grub['grubenv_entry']])
        if grub.get('boot_params'):
            grub_rows.append(['GRUB_CMDLINE_LINUX_DEFAULT', grub['boot_params'][:120]])
        if grub.get('antiforensic_params'):
            grub_rows.append(['⚠ Anti-Forensik-Parameter', ', '.join(grub['antiforensic_params'])])
        else:
            grub_rows.append(['Anti-Forensik-Parameter', 'Keine erkannt'])
        if grub.get('sources'):
            grub_rows.append(['Quellen', ', '.join(grub['sources'])])
        if grub_rows:
            from reportlab.platypus import Table as RLTable, TableStyle as RLTS
            from reportlab.lib.colors import HexColor
            data = [[r[0], r[1]] for r in grub_rows]
            tbl = RLTable(data, colWidths=[60*mm, W - 60*mm])
            style_cmds = [
                ('BACKGROUND',   (0, 0), (0, -1), _rl_color_from_tuple(C_LIGHT_GREY)),
                ('FONTNAME',     (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME',     (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE',     (0, 0), (-1, -1), 8),
                ('GRID',         (0, 0), (-1, -1), 0.3, _rl_color_from_tuple((0xDD/255,)*3)),
                ('LEFTPADDING',  (0, 0), (-1, -1), 5),
                ('TOPPADDING',   (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
            ]
            # Anti-Forensik-Zeile rot markieren
            for idx, r in enumerate(grub_rows):
                if '⚠' in r[0]:
                    style_cmds.append(('BACKGROUND', (0, idx), (-1, idx),
                                       _rl_color_from_tuple(C_RED_L)))
                    style_cmds.append(('TEXTCOLOR',  (0, idx), (-1, idx),
                                       _rl_color_from_tuple(C_RED)))
            tbl.setStyle(RLTS(style_cmds))
            story.append(tbl)
        else:
            story.append(_body('Keine GRUB-Konfiguration gefunden (kein grub.cfg / grubenv im Image).'))
        story.append(_spacer(5))

        # ── Kernel Compile-Flags ──────────────────────────────────────────────────
        story.append(_h2('Einkompilierte Kernel-Flags (/boot/config-*)'))
        story.append(_spacer(2))
        flags_map = getattr(ctx, 'kernel_compile_flags', {})
        all_kernels = getattr(ctx, 'all_kernel_versions', [])
        if flags_map:
            rows = [['Kernel-Version', 'Aktive Anti-Forensik-Flags', 'Bewertung']]
            for kver in all_kernels:
                info = flags_map.get(kver)
                if info is None:
                    rows.append([kver, '—  (keine /boot/config gefunden)', 'Unbekannt'])
                elif info.get('has_antiforensics'):
                    rows.append([kver,
                                 '\n'.join(info['active_flags']),
                                 '⚠ VERDAECHTIG'])
                else:
                    rows.append([kver, 'Keine Anti-Forensik-Flags aktiv', 'Unauffaellig'])
            tbl = _table(rows, [55*mm, 95*mm, 20*mm])
            # Rote Zeilen fuer verdaechtige Kernel
            from reportlab.platypus import TableStyle as RLTS2
            extra = []
            for i, kver in enumerate(all_kernels, 1):
                info = flags_map.get(kver, {})
                if info.get('has_antiforensics'):
                    extra.append(('BACKGROUND', (0, i), (-1, i),
                                   _rl_color_from_tuple(C_RED_L)))
                    extra.append(('TEXTCOLOR',  (0, i), (-1, i),
                                   _rl_color_from_tuple(C_RED)))
            if extra:
                tbl.setStyle(RLTS2(tbl._style._cmds + extra))
            story.append(tbl)
        elif all_kernels:
            story.append(_body(f'Kernel gefunden: {", ".join(all_kernels)}  — '
                               f'keine /boot/config-* Dateien im Image vorhanden.'))
        else:
            story.append(_body('Keine installierten Kernel erkannt.'))
        story.append(_spacer(5))

        # ── Swap-Konfiguration ────────────────────────────────────────────────────
        story.append(_h2('Swap-Konfiguration (/etc/fstab)'))
        story.append(_spacer(2))
        swap = getattr(ctx, 'swap_config', {})
        if swap.get('found'):
            entries = swap.get('entries', [])
            swap_data = [['Typ', 'Pfad / UUID', 'Groesse']]
            for e in entries:
                swap_data.append([e.get('type', '—'), e.get('path', '—'),
                                  f"{e.get('size_mb', 0):.0f} MB" if e.get('size_mb') else '—'])
            story.append(_table(swap_data, [35*mm, 110*mm, 25*mm]))
        else:
            story.append(_body(
                '❌  Kein Swap konfiguriert.  Auf Desktop-Systemen verdaechtig — '
                'RAM-Forensik aus Swap-Partition nicht moeglich.'
            ))
        story.append(_spacer(5))

        # ── Ausstehender Reboot & Kernel-Diskrepanz ───────────────────────────────
        reboot_pending_alt = getattr(ctx, 'reboot_pending', False)
        loaded_kernel_alt  = getattr(ctx, 'loaded_kernel_from_logs', '')
        active_kernel_alt  = grub.get('active_kernel', '')
        if reboot_pending_alt or (active_kernel_alt and loaded_kernel_alt
                                  and active_kernel_alt != loaded_kernel_alt):
            story.append(_h2('Kernel-Status & Reboot'))
            story.append(_spacer(2))
            state_rows = []
            state_rows.append(['GRUB-Default-Kernel', active_kernel_alt or '—'])
            state_rows.append(['Geladen laut Logs',   loaded_kernel_alt or '—'])
            if active_kernel_alt and loaded_kernel_alt and active_kernel_alt != loaded_kernel_alt:
                state_rows.append(['⚠ Kernel-Diskrepanz',
                                   f'GRUB={active_kernel_alt}  ≠  Geladen={loaded_kernel_alt}'])
            if reboot_pending_alt:
                state_rows.append(['⚠ Pending Reboot',
                                   'Kernel-Update installiert — kein Neustart erfolgt'])
            from reportlab.platypus import Table as RLT3, TableStyle as RLTS3
            data3 = [[r[0], r[1]] for r in state_rows]
            t3 = RLT3(data3, colWidths=[60*mm, W - 60*mm])
            cmds3 = [
                ('BACKGROUND',   (0, 0), (0, -1), _rl_color_from_tuple(C_LIGHT_GREY)),
                ('FONTNAME',     (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME',     (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE',     (0, 0), (-1, -1), 8),
                ('GRID',         (0, 0), (-1, -1), 0.3, _rl_color_from_tuple((0xDD/255,)*3)),
                ('LEFTPADDING',  (0, 0), (-1, -1), 5),
                ('TOPPADDING',   (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
            ]
            for idx, r in enumerate(state_rows):
                if '⚠' in r[0]:
                    cmds3.append(('BACKGROUND', (0, idx), (-1, idx),
                                   _rl_color_from_tuple(C_ORANGE_L)))
                    cmds3.append(('TEXTCOLOR',  (0, idx), (-1, idx),
                                   _rl_color_from_tuple(C_ORANGE)))
            t3.setStyle(RLTS3(cmds3))
            story.append(t3)
            story.append(_spacer(5))

        # ── /dev/null Symlinks ────────────────────────────────────────────────────
        symlinks_alt = getattr(ctx, 'primary_symlinks', {})
        devnull_symlinks = {p: t for p, t in symlinks_alt.items() if '/dev/null' in t}
        story.append(_h2('/dev/null Symlinks auf Log-Dateien'))
        story.append(_spacer(2))
        if devnull_symlinks:
            rows = [['Pfad', 'Symlink-Ziel', 'Bewertung']]
            for path, target in sorted(devnull_symlinks.items()):
                rows.append([path, target, '⚠ KRITISCH — keine Protokollierung'])
            tbl_sym = _table(rows, [65*mm, 55*mm, 50*mm])
            story.append(tbl_sym)
        else:
            story.append(_body('Keine /dev/null Symlinks auf Log-Dateien erkannt.'))
        story.append(_spacer(3))
        story.append(_body(
            'Methode: fls -r (Typ l/l = Symlink) + icat zum Lesen des Symlink-Ziels. '
            'Forensisch unveraendert — kein Mounting des Images.'
        ))
        story.append(PageBreak())

    # ── AUSKOMMENTIERT: Alt Seite 7 — Timeline (jetzt Seite 3) ──────────────
    # Timeline wurde auf Seite 3 vorgezogen (direkt nach Executive Summary).
    # Reaktivieren: if False entfernen.
    if False:
        story.append(_h1('Forensische Timeline'))
        story.append(_spacer(3))
        story.append(_body('Alle Zeitstempel sind in UTC.'))
        story.append(PageBreak())

    # ── AUSKOMMENTIERT: Alt Seite 8 — System-Profiling + Pipeline-Status ─────
    # System-Profiling jetzt auf Seite 7, Pipeline-Status in Anhang A.
    # Reaktivieren: if False entfernen.
    if False:
        story.append(_h1('System-Profiling & Pipeline-Status'))
        story.append(_spacer(4))
        story.append(PageBreak())

    # ── Anhang B: Parser-Statistik ────────────────────────────────────────────
    story.append(_h1('B — Parser-Statistik'))
    story.append(_spacer(3))
    story.append(_body(
        'Uebersicht aller 38 Parser + Hayabusa — '
        'welche aktiv waren und wie viele Events sie extrahiert haben.'
    ))
    story.append(_spacer(4))

    # ── AUSKOMMENTIERT: Alt Seite 9 — vollstaendiges CoC-Protokoll ───────────
    # Ersetzt durch Anhang C (Kurzform + Verweis auf chain_of_custody.pdf).
    # Reaktivieren: if False entfernen.
    if False:
        story.append(_h1('Pipeline-Ausfuehrungsprotokoll'))
        coc_tmp = ctx.coc
        if coc_tmp:
            rows = [['Stufe', 'Aktion', 'Zeitstempel']]
            for entry in coc_tmp.entries:
                rows.append([entry.stage, entry.action[:70],
                             entry.timestamp.strftime('%H:%M:%S')])
            story.append(_table(rows, [35*mm, 100*mm, 35*mm]))
        story.append(PageBreak())

    # ── Anhang B: Parser-Statistik (Inhalt) ──────────────────────────────────
    story.append(_h1('Parser-Statistik'))
    story.append(_spacer(3))
    story.append(_body('Übersicht aller 38 Parser + Hayabusa (Stage 3.3) — '
                       'welche aktiv waren und wie viele Events sie extrahiert haben.'))
    story.append(_spacer(4))

    # ── Hayabusa Info-Box ─────────────────────────────────────────────────────
    hayabusa_status = ctx.stage_status.get('stage_03_3', 'UNBEKANNT — Stage 3.3 nicht ausgeführt')
    hayabusa_hits   = ctx.hayabusa_hits

    if hayabusa_hits > 0:
        haya_bg    = C_GREEN_L
        haya_border = C_GREEN
        haya_label  = f'Hayabusa (Stage 3.3): AKTIV — {hayabusa_hits} Sigma-Treffer'
    else:
        haya_bg    = C_YELLOW_L
        haya_border = C_ORANGE
        haya_label  = f'Hayabusa (Stage 3.3): INFORMATION — {hayabusa_status}'

    haya_box = Table(
        [[Paragraph(
            f'<font size="9"><b>{haya_label}</b></font>',
            _normal_style()
        )]],
        colWidths=[W]
    )
    haya_box.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), _rl_color_from_tuple(haya_bg)),
        ('BOX',           (0, 0), (-1, -1), 1.5, _rl_color_from_tuple(haya_border)),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
    ]))
    story.append(haya_box)
    story.append(_spacer(5))

    # ── Parser-Tabelle ────────────────────────────────────────────────────────
    parser_counts = ctx.parser_stats

    all_parsers = [
        'syslog','auth','journald','kern','boot','daemon','wtmp','lastlog',
        'dpkg','apt','yum','dnf','pacman',
        'apache_access','apache_error','nginx_access','nginx_error',
        'mysql','postgresql','mongodb',
        'audit','fail2ban','ufw','cron',
        'bash_history','zsh_history','fish_history','utmp',
        'ssh','postfix','ftp','samba','openvpn',
        'docker','containerd','iis','evtx','plaso_fallback',
        'hayabusa',
    ]
    rows = [['Parser', 'Log-Datei / Quelle', 'Events', 'Status']]
    for name in all_parsers:
        count = parser_counts.get(name, 0)
        if name == 'hayabusa':
            source = 'EVTX (Sigma-Rules)'
            status = f'Aktiv — {count} Sigma-Treffer' if count > 0 else 'Übersprungen — keine EVTX-Dateien'
        elif name == 'plaso_fallback' and count > 0:
            source = f'{name}.log'
            status = 'Fallback aktiv'
        else:
            source = f'{name}.log'
            status = 'Aktiv' if count > 0 else 'Nicht vorhanden'
        rows.append([name, source, str(count), status])

    story.append(_table(rows, [38*mm, 52*mm, 20*mm, 60*mm]))
    story.append(PageBreak())

    # ── Anhang C: Chain of Custody (Kurzform) ─────────────────────────────────
    story.append(_h1('C — Chain of Custody (Kurzform)'))
    story.append(_spacer(3))
    story.append(_body(
        'Vollstaendiges Chain-of-Custody-Protokoll mit allen Einzelschritten: '
        'chain_of_custody.pdf'
    ))
    story.append(_spacer(4))
    coc = ctx.coc
    if coc:
        kv_coc = [
            ['Dateiname', coc.file_name],
            ['SHA256',    coc.sha256],
            ['MD5',       coc.md5],
            ['Groesse',   f'{coc.size_gb:.2f} GB'],
            ['Startzeit', coc.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Case-ID',   case_dir.name],
            ['Protokoll', f'{len(coc.entries)} Eintraege — siehe chain_of_custody.pdf'],
        ]
        story.append(_kv_table(kv_coc, W, _rl_color))
        story.append(_spacer(4))
        story.append(_body(
            'Rechtlicher Hinweis: Die Integritaet des Beweismittels wurde durch '
            'SHA256- und MD5-Hashwerte gesichert. Das vollstaendige Ausfuehrungsprotokoll '
            'ist Bestandteil der chain_of_custody.pdf.'
        ))

    # ── AUSKOMMENTIERT: Alt Seite 11 — YARA + Erweiterte IOCs ────────────────
    # YARA-Treffer sind Teil von ctx.antiforensics_hits (type='yara_match').
    # Erweiterte IOC-Tabelle ist Duplikat von Seite 5. Beide entfernt.
    # Reaktivieren: if False entfernen.
    if False:
        story.append(_h1('YARA-Treffer & Erweiterte IOCs'))
        yara_hits_list = [h for h in ctx.antiforensics_hits if h.get('type') == 'yara_match']
        if yara_hits_list:
            rows = [['YARA-Regel', 'Betroffene Datei', 'Details', 'Schwere']]
            for h in yara_hits_list[:20]:
                rows.append([h.get('rule', '')[:30], h['file'][-40:],
                             h['details'][:60], h['severity']])
            story.append(_table(rows, [40*mm, 55*mm, 60*mm, 15*mm]))
        story.append(_h2('Erweiterte IOC-Tabelle'))
        if ctx.iocs:
            rows = [['Typ', 'Wert', 'Parser', 'Kontext']]
            for ioc in ctx.iocs[:30]:
                rows.append([ioc.type, ioc.value[:40], ioc.source[:20], ioc.context[:40]])
            story.append(_table(rows, [22*mm, 64*mm, 25*mm, 59*mm]))

    # ── PDF bauen ─────────────────────────────────────────────────────────────
    def _on_page(canv, doc):
        _draw_header(canv, A4, case_id, created, quality)
        _draw_footer(canv, A4)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    log.info(f'  report.pdf → {out_file}')


def _draw_header(canv, page_size, case_id, created, quality):
    from reportlab.lib.units import mm
    W, H = page_size
    canv.saveState()
    canv.setFillColorRGB(*C_DARK_BLUE)
    canv.rect(0, H - 28*mm, W, 28*mm, fill=1, stroke=0)
    canv.setFillColorRGB(*C_WHITE)
    canv.setFont('Helvetica-Bold', 13)
    canv.drawString(15*mm, H - 13*mm, 'DFIR ANALYSE-REPORT')
    canv.setFont('Helvetica', 8)
    canv.setFillColorRGB(*C_LIGHT_BLUE)
    canv.drawString(15*mm, H - 21*mm, f'Case-ID: {case_id}  |  Erstellt: {created}  |  VERTRAULICH')
    badge_color = C_GREEN if quality == 'SEHR GUT' else C_ORANGE if quality == 'GUT' else C_RED
    canv.setFillColorRGB(*badge_color)
    canv.roundRect(W - 75*mm, H - 22*mm, 60*mm, 10*mm, 2*mm, fill=1, stroke=0)
    canv.setFillColorRGB(*C_WHITE)
    canv.setFont('Helvetica-Bold', 8)
    canv.drawCentredString(W - 45*mm, H - 16*mm, f'QUALITÄT: {quality}')
    canv.restoreState()


def _draw_footer(canv, page_size):
    from reportlab.lib.units import mm
    W, H = page_size
    canv.saveState()
    canv.setStrokeColorRGB(*C_LIGHT_GREY)
    canv.setLineWidth(0.5)
    canv.line(15*mm, 18*mm, W - 15*mm, 18*mm)
    canv.setFillColorRGB(*C_MID_GREY)
    canv.setFont('Helvetica', 7)
    canv.drawString(15*mm, 12*mm,
                    'DFIR Analyse-Pipeline v3.0  |  Automatisch generiert  |  Nicht für die Öffentlichkeit')
    canv.drawRightString(W - 15*mm, 12*mm, f'Seite {canv.getPageNumber()}')
    canv.restoreState()


def _banner(text, bg, fg, size, width):
    from reportlab.platypus import Table, TableStyle
    t = Table([[text]], colWidths=[width])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), _rl_color_from_tuple(bg)),
        ('TEXTCOLOR',  (0,0), (-1,-1), _rl_color_from_tuple(fg)),
        ('FONTNAME',   (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), size),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0),(-1,-1), 8),
    ]))
    return t


def _kv_table(rows, width, rl_fn):
    from reportlab.platypus import Table, TableStyle
    data = [[r[0], r[1]] for r in rows]
    t = Table(data, colWidths=[50*_mm_val(), width - 50*_mm_val()])
    t.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (0,-1), _rl_color_from_tuple(C_LIGHT_GREY)),
        ('BACKGROUND',  (1,0), (1,-1), _rl_color_from_tuple(C_WHITE)),
        ('FONTNAME',    (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTNAME',    (1,0), (1,-1), 'Helvetica'),
        ('FONTSIZE',    (0,0), (-1,-1), 8),
        ('GRID',        (0,0), (-1,-1), 0.3, _rl_color_from_tuple((0xDD/255,)*3)),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING',(0,0), (-1,-1), 5),
        ('TOPPADDING',  (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0),(-1,-1), 4),
    ]))
    return t


def _stat_boxes(stats, width, rl_fn):
    from reportlab.platypus import Table, TableStyle, Paragraph
    n    = len(stats)
    cell_w = width / n
    data = [[Paragraph(f'<font size="22" color="#{_hex(C_MID_BLUE)}"><b>{v}</b></font>'
                       f'<br/><font size="8" color="#{_hex(C_MID_GREY)}">{label}</font>',
                       _normal_style())
             for v, label in stats]]
    t = Table(data, colWidths=[cell_w]*n)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), _rl_color_from_tuple(C_LIGHT_GREY)),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0),(-1,-1), 8),
    ]))
    return t


def _rl_color_from_tuple(t):
    from reportlab.lib.colors import Color
    return Color(*t)


def _hex(rgb_tuple) -> str:
    return ''.join(f'{int(v*255):02X}' for v in rgb_tuple)


def _mm_val():
    from reportlab.lib.units import mm
    return mm


def _normal_style():
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_CENTER
    styles = getSampleStyleSheet()
    s = styles['Normal'].clone('centered')
    s.alignment = TA_CENTER
    return s


def _normal_style_left():
    """Links-ausgerichteter Paragraph-Style — fuer Befund-Boxen."""
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_LEFT
    styles = getSampleStyleSheet()
    s = styles['Normal'].clone('left_aligned')
    s.alignment = TA_LEFT
    return s


# ── Chain of Custody PDF ──────────────────────────────────────────────────────

def _generate_coc_pdf(ctx: PipelineContext, case_dir: Path) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, PageBreak)
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        return

    out_file = case_dir / 'chain_of_custody.pdf'
    doc      = SimpleDocTemplate(str(out_file), pagesize=A4,
                                  leftMargin=15*mm, rightMargin=15*mm,
                                  topMargin=35*mm, bottomMargin=22*mm)
    styles   = getSampleStyleSheet()
    story    = []
    coc      = ctx.coc
    case_id  = case_dir.name
    created  = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    quality  = evaluate_quality(ctx)

    W = A4[0] - 30*mm

    story.append(_banner('CHAIN OF CUSTODY', C_DARK_BLUE, C_WHITE, 20, W))
    story.append(Spacer(1, 6*mm))

    if coc:
        kv = [
            ['Dateiname', coc.file_name],
            ['SHA256',    coc.sha256],
            ['MD5',       coc.md5],
            ['Größe',     f'{coc.size_gb:.2f} GB'],
            ['Startzeit', coc.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Case-ID',   case_id],
        ]
        data = [[r[0], r[1]] for r in kv]
        t = Table(data, colWidths=[50*mm, W - 50*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (0,-1), _rl_color_from_tuple(C_LIGHT_GREY)),
            ('FONTNAME',    (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME',    (1,0), (1,-1), 'Helvetica'),
            ('FONTSIZE',    (0,0), (-1,-1), 9),
            ('GRID',        (0,0), (-1,-1), 0.3, _rl_color_from_tuple((0xDD/255,)*3)),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING',  (0,0), (-1,-1), 4),
            ('BOTTOMPADDING',(0,0),(-1,-1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 6*mm))

        rows = [['Stufe', 'Aktion', 'Zeitstempel']]
        for entry in coc.entries:
            rows.append([entry.stage, entry.action[:80],
                         entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
        t2 = Table(rows, colWidths=[35*mm, 105*mm, 30*mm], repeatRows=1)
        t2.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0), _rl_color_from_tuple(C_DARK_BLUE)),
            ('TEXTCOLOR',   (0,0), (-1,0), _rl_color_from_tuple(C_WHITE)),
            ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME',    (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',    (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),
             [_rl_color_from_tuple(C_WHITE), _rl_color_from_tuple(C_LIGHT_GREY)]),
            ('GRID',        (0,0), (-1,-1), 0.3, _rl_color_from_tuple((0xDD/255,)*3)),
            ('LEFTPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING',  (0,0), (-1,-1), 4),
            ('BOTTOMPADDING',(0,0),(-1,-1), 4),
        ]))
        story.append(t2)

        # Extrahierte Dateien + Hashwerte
        if coc.extracted_file_hashes:
            story.append(Spacer(1, 6*mm))
            story.append(_banner(
                f'EXTRAHIERTE DATEIEN — HASHWERTE ({len(coc.extracted_file_hashes)} Dateien)',
                C_MID_BLUE, C_WHITE, 11, W))
            story.append(Spacer(1, 3*mm))
            hash_rows = [['Dateiname', 'SHA256']]
            for fname, sha in sorted(coc.extracted_file_hashes.items()):
                hash_rows.append([fname[:50], sha])
            t3 = Table(hash_rows, colWidths=[60*mm, W - 60*mm], repeatRows=1)
            t3.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,0), _rl_color_from_tuple(C_MID_BLUE)),
                ('TEXTCOLOR',     (0,0), (-1,0), _rl_color_from_tuple(C_WHITE)),
                ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTNAME',      (0,1), (-1,-1), 'Helvetica'),
                ('FONTSIZE',      (0,0), (-1,-1), 7),
                ('ROWBACKGROUNDS',(0,1), (-1,-1),
                 [_rl_color_from_tuple(C_WHITE), _rl_color_from_tuple(C_LIGHT_GREY)]),
                ('GRID',          (0,0), (-1,-1), 0.3, _rl_color_from_tuple((0xDD/255,)*3)),
                ('LEFTPADDING',   (0,0), (-1,-1), 5),
                ('TOPPADDING',    (0,0), (-1,-1), 3),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(t3)

    def _on_page(canv, doc):
        _draw_header(canv, A4, case_id, created, quality)
        _draw_footer(canv, A4)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    log.info(f'  chain_of_custody.pdf → {out_file}')


# ── Timesketch Upload ─────────────────────────────────────────────────────────

def _upload_timesketch(ctx: PipelineContext, case_dir: Path) -> None:
    try:
        import yaml
        cfg_path = Path(__file__).parent.parent / 'config.yaml'
        if not cfg_path.exists():
            _write_timesketch_link(case_dir, 'http://localhost:5000')
            return
        with open(cfg_path) as f:
            cfg = yaml.safe_load(f)
        ts_cfg  = cfg.get('timesketch', {})
        host    = ts_cfg.get('host', 'http://localhost:5000')
        user    = ts_cfg.get('username', 'admin')
        passwd  = ts_cfg.get('password', 'changeme')
        sketch  = ts_cfg.get('sketch_id', 1)

        from timesketch_api_client import client as ts_client
        cli    = ts_client.TimesketchApi(host, user, passwd)
        sk     = cli.get_sketch(sketch)
        events = []
        for e in ctx.normalized_events[:50000]:
            events.append({
                'datetime':    e.timestamp.isoformat(),
                'timestamp_desc': e.event_type,
                'message':     e.message,
                'source':      e.source,
            })
        sk.add_timeline_from_json(json.dumps(events),
                                  timeline_name=f'DFIR_{case_dir.name}')
        url = f'{host}/sketch/{sketch}/explore'
        log.info(f'  Timesketch Upload abgeschlossen → {url}')
        _write_timesketch_link(case_dir, url)

    except Exception as e:
        log.warning(f'  Timesketch Upload fehlgeschlagen: {e}')
        _write_timesketch_link(case_dir, 'http://localhost:5000')


def _write_timesketch_link(case_dir: Path, url: str) -> None:
    (case_dir / 'timesketch_link.txt').write_text(
        f'Timesketch URL: {url}\n'
        f'Erstellt: {datetime.utcnow().isoformat()}Z\n'
    )


try:
    from reportlab.platypus import Paragraph as _Paragraph
except ImportError:
    pass
