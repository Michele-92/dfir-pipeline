import csv
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

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


def _classify_event(event) -> str | None:
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
        ['Qualität',   quality],       ['IOC-Qualität', ctx.ioc_quality],
    ]
    story.append(_h2('Case-Informationen'))
    story.append(_spacer(2))
    story.append(_kv_table(kv1, W, _rl_color))
    story.append(_spacer(6))

    kv2 = [
        ['OS',           ctx.os_name or '–'],
        ['Kernel',       ctx.kernel_version or '–'],
        ['Hostname',     ctx.hostname or '–'],
        ['Zeitzone',     ctx.timezone],
        ['Autopsy',      'Gelaufen' if ctx.autopsy_ran else ctx.autopsy_reason[:60]],
        ['TSK-Fallback', 'Aktiv' if ctx.tsk_fallback_used else 'Nicht nötig'],
    ]
    story.append(_h2('System-Information'))
    story.append(_spacer(2))
    story.append(_kv_table(kv2, W, _rl_color))
    story.append(PageBreak())

    # ── Seite 2: Executive Summary ───────────────────────────────────────────
    story.append(_h1('Executive Summary'))
    story.append(_spacer(4))
    stats = [
        (f'{ctx.total_log_lines:,}', 'Log-Zeilen'),
        (f'{ctx.parsed_events:,}',   'Events'),
        (str(len(ctx.anomalies)),    'Anomalien'),
        (str(len(ctx.iocs)),         'IOCs'),
        (str(len(ctx.mitre_hits)),   'MITRE Techniken'),
    ]
    story.append(_stat_boxes(stats, W, _rl_color))
    story.append(_spacer(6))

    critical = [e for e in ctx.normalized_events if e.severity == 'critical']
    high     = [e for e in ctx.normalized_events if e.severity == 'high']
    top_events = (critical + high)[:10]
    if top_events:
        story.append(_h2('Kritische Funde'))
        story.append(_spacer(2))
        rows = [['Schwere', 'Zeitstempel', 'Beschreibung', 'MITRE']]
        for e in top_events:
            rows.append([
                e.severity.upper(),
                e.timestamp.strftime('%Y-%m-%d %H:%M'),
                e.message[:80],
                ', '.join(e.mitre_tags[:2]),
            ])
        story.append(_table(rows, [25*mm, 35*mm, 85*mm, 25*mm]))
        story.append(_spacer(4))

    if ctx.antiforensics_hits or ctx.mitre_hits:
        story.append(_h2('Sofortmaßnahmen'))
        story.append(_spacer(2))
        recs = []
        if ctx.antiforensics_hits:
            recs.append('Beweise sichern — Anti-Forensics-Techniken erkannt')
        if any(h['technique_id'].startswith('T1003') for h in ctx.mitre_hits):
            recs.append('Alle Passwörter sofort ändern (Credential Dumping erkannt)')
        if any(h['technique_id'] == 'T1098' for h in ctx.mitre_hits):
            recs.append('Neue Benutzerkonten überprüfen und ggf. deaktivieren')
        if ctx.tsk_fallback_used:
            recs.append('IOC-Qualität MITTEL — manuelle Nachprüfung empfohlen')
        for i, r in enumerate(recs, 1):
            story.append(_body(f'{i}. {r}'))
    story.append(PageBreak())

    # ── Seite 3: Forensische Befunde (Stage 8.5) ────────────────────────────
    story.append(_h1('Forensische Befunde'))
    story.append(_spacer(3))
    story.append(_body(
        'Automatisch erkannte Anomalien basierend auf MACtime-Timestamps, '
        'Anti-Forensics-Indikatoren und CVE-Zeitfenstern.'
    ))
    story.append(_spacer(4))

    if ctx.forensic_findings:
        sev_color = {'CRITICAL': C_RED_L, 'HIGH': C_ORANGE_L, 'MEDIUM': C_YELLOW_L}
        rows = [['Schwere', 'Regel', 'Datei', 'Beschreibung']]
        for f in ctx.forensic_findings[:30]:
            rows.append([
                f.severity,
                f.rule[:25],
                f.file[:40],
                f.description[:80],
            ])
        t = _table(rows, [20*mm, 35*mm, 45*mm, 70*mm])
        story.append(t)
        story.append(_spacer(4))
        story.append(_body(
            f'Vollständige Befunde mit Evidence-Kontext: forensic_findings.json'
        ))
    else:
        story.append(_body('Keine forensischen Befunde erkannt.'))
    story.append(PageBreak())

    # ── Seite 4: IOC-Liste ───────────────────────────────────────────────────
    story.append(_h1('Indicators of Compromise (IOCs)'))
    story.append(_spacer(3))
    story.append(_body(f'IOC-Qualität: {ctx.ioc_quality} | '
                       f'{len(ctx.iocs)} IOCs aus allen Quellen extrahiert'))
    story.append(_spacer(4))

    ips      = [i for i in ctx.iocs if i.type in ('ip', 'ipv6')]
    domains  = [i for i in ctx.iocs if i.type in ('domain', 'url')]
    hashes   = [i for i in ctx.iocs if i.type in ('hash_md5', 'hash_sha256')]
    others   = [i for i in ctx.iocs if i.type in ('email', 'cve', 'registry_key')]

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
    story.append(PageBreak())

    # ── Seite 5: Anti-Forensics & ML ────────────────────────────────────────
    story.append(_h1('Anti-Forensics & ML-Anomalien'))
    story.append(_spacer(3))
    if ctx.antiforensics_hits:
        story.append(_body(f'⚠ {len(ctx.antiforensics_hits)} Anti-Forensics-Techniken erkannt!'))
        story.append(_spacer(3))
        rows = [['Technik', 'Datei / Quelle', 'Details', 'Schwere']]
        for h in ctx.antiforensics_hits[:20]:
            rows.append([h['type'], h['file'][:40], h['details'][:60], h['severity']])
        story.append(_table(rows, [35*mm, 45*mm, 70*mm, 20*mm]))
        story.append(_spacer(5))

    story.append(_h2('ML-Anomalien (Isolation Forest)'))
    story.append(_spacer(2))
    story.append(_body('Isolation Forest markiert statistisch auffällige Ereignisse. '
                       'Score 0.0 = normal, 1.0 = sehr verdächtig.'))
    story.append(_spacer(3))
    if ctx.anomalies:
        rows = [['Score', 'Zeitstempel', 'Event', 'Quelle']]
        for e in sorted(ctx.anomalies, key=lambda x: x.anomaly_score, reverse=True)[:20]:
            rows.append([
                f'{e.anomaly_score:.2f}',
                e.timestamp.strftime('%Y-%m-%d %H:%M'),
                e.message[:70],
                e.source[:20],
            ])
        story.append(_table(rows, [18*mm, 35*mm, 95*mm, 22*mm]))
    else:
        story.append(_body('Keine Anomalien erkannt.'))
    story.append(PageBreak())

    # ── Seite 6: Forensische Timeline ───────────────────────────────────────
    story.append(_h1('Forensische Timeline'))
    story.append(_spacer(3))
    story.append(_body('Alle Zeitstempel sind in UTC. Die Timeline zeigt die '
                       'wichtigsten Ereignisse chronologisch sortiert.'))
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
    ts_url = f'http://localhost:5000/sketch/{1}/explore'
    ts_box = Table(
        [[Paragraph(
            f'<font color="#{_hex(C_MID_BLUE)}"><b>Interaktive Timeline (Timesketch)</b></font><br/>'
            f'<font size="9">{ts_url}</font>',
            _normal_style()
        )]],
        colWidths=[W]
    )
    ts_box.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), _rl_color_from_tuple(C_LIGHT_BLUE)),
        ('BOX',          (0,0), (-1,-1), 1.5, _rl_color_from_tuple(C_MID_BLUE)),
        ('TOPPADDING',   (0,0), (-1,-1), 8),
        ('BOTTOMPADDING',(0,0), (-1,-1), 8),
        ('LEFTPADDING',  (0,0), (-1,-1), 10),
    ]))
    story.append(ts_box)
    story.append(PageBreak())

    # ── Seite 7: System-Profiling & Pipeline-Status ──────────────────────────
    story.append(_h1('System-Profiling & Pipeline-Status'))
    story.append(_spacer(4))
    kv3 = [
        ['OS-Familie',   ctx.os_family or '–'],
        ['OS-Name',      ctx.os_name or '–'],
        ['Kernel',       ctx.kernel_version or '–'],
        ['Hostname',     ctx.hostname or '–'],
        ['Zeitzone',     ctx.timezone],
        ['Image-Format', ctx.file_type],
        ['Image-Größe',  f'{ctx.file_size_gb:.2f} GB'],
    ]
    story.append(_h2('System-Profiling'))
    story.append(_spacer(2))
    story.append(_kv_table(kv3, W, _rl_color))
    story.append(_spacer(6))

    story.append(_h2('Pipeline-Status aller Stufen'))
    story.append(_spacer(2))
    stage_rows = [['Stufe', 'Status', 'Anmerkung']]
    for stage_name, status in ctx.stage_status.items():
        err = ctx.stage_errors.get(stage_name, '')
        stage_rows.append([stage_name, status, err[:60]])
    story.append(_table(stage_rows, [35*mm, 40*mm, 95*mm]))
    story.append(PageBreak())

    # ── Seite 8: Pipeline-Ausführungsprotokoll ───────────────────────────────
    story.append(_h1('Pipeline-Ausführungsprotokoll'))
    story.append(_para('(Teil der forensischen Chain of Custody)', 'Italic'))
    story.append(_spacer(4))
    coc = ctx.coc
    if coc:
        kv4 = [
            ['Dateiname', coc.file_name],
            ['SHA256',    coc.sha256],
            ['MD5',       coc.md5],
            ['Größe',     f'{coc.size_gb:.2f} GB'],
            ['Startzeit', coc.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ]
        story.append(_h2('Beweisdaten'))
        story.append(_spacer(2))
        story.append(_kv_table(kv4, W, _rl_color))
        story.append(_spacer(5))

        story.append(_h2('Ausführungsprotokoll'))
        story.append(_spacer(2))
        rows = [['Stufe', 'Aktion', 'Zeitstempel']]
        for entry in coc.entries:
            rows.append([
                entry.stage,
                entry.action[:70],
                entry.timestamp.strftime('%H:%M:%S'),
            ])
        story.append(_table(rows, [35*mm, 100*mm, 35*mm]))
        story.append(_spacer(5))
        story.append(_body('Rechtlicher Hinweis: Dieses Dokument wurde automatisch '
                           'generiert. Die Integrität des Beweismittels wurde durch '
                           'SHA256- und MD5-Hashwerte gesichert.'))
    story.append(PageBreak())

    # ── Seite 9: Parser-Statistik ────────────────────────────────────────────
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

    # ── Seite 10: YARA-Treffer & Erweiterte IOCs ─────────────────────────────
    story.append(_h1('YARA-Treffer & Erweiterte IOCs'))
    story.append(_spacer(3))

    yara_hits = [h for h in ctx.antiforensics_hits if h.get('type') == 'yara_match']
    if yara_hits:
        story.append(_h2('YARA-Treffer'))
        story.append(_spacer(2))
        rows = [['YARA-Regel', 'Betroffene Datei', 'Details', 'Schwere']]
        for h in yara_hits[:20]:
            rows.append([
                h.get('rule', '')[:30],
                h['file'][-40:],
                h['details'][:60],
                h['severity'],
            ])
        story.append(_table(rows, [40*mm, 55*mm, 60*mm, 15*mm]))
        story.append(_spacer(5))
    else:
        story.append(_body('Keine YARA-Treffer.'))
        story.append(_spacer(4))

    story.append(_h2('Erweiterte IOC-Tabelle'))
    story.append(_spacer(2))
    if ctx.iocs:
        rows = [['Typ', 'Wert', 'Parser', 'Kontext']]
        for ioc in ctx.iocs[:30]:
            rows.append([
                ioc.type,
                ioc.value[:40],
                ioc.source[:20],
                ioc.context[:40],
            ])
        story.append(_table(rows, [22*mm, 64*mm, 25*mm, 59*mm]))
    else:
        story.append(_body('Keine IOCs extrahiert.'))

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
