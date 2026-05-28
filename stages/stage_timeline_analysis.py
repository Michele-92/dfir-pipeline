import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from models.forensic_finding import ForensicFinding
from models.pipeline_context import PipelineContext
from utils.event_store import EventStore

log = logging.getLogger(__name__)

# Systempfade die bei Modifikation verdächtig sind
SYSTEM_PATHS = ['/etc/', '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/lib/', '/usr/lib/']
STAGING_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/']

# Dateiendung → erwartete Sorter-Kategorie
# Wenn Sorter etwas anderes erkennt → Mismatch → verdächtig
EXT_EXPECTED = {
    '.jpg': 'images',  '.jpeg': 'images', '.png': 'images',
    '.gif': 'images',  '.bmp': 'images',
    '.pdf': 'documents',
    '.txt': 'text',    '.log':  'text',   '.conf': 'text',  '.csv': 'text',
    '.zip': 'archive', '.tar':  'archive', '.gz': 'archive', '.bz2': 'archive',
    '.mp3': 'audio',   '.wav':  'audio',
    '.mp4': 'video',   '.avi':  'video',
    '.sh':  'exec',    '.py':   'exec',
}

# Regex zum Extrahieren der MACB-Flags aus der message: "[m..b] /pfad (123 bytes)"
_MACB_RE = re.compile(r'^\[([macb.]+)\]')


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 8.5: Forensischer Analyse-Algorithmus')

    if not ctx.events_db_path or not ctx.events_db_path.exists():
        log.warning('  Keine events.db — Stage 8.5 übersprungen')
        ctx.stage_status['stage_8.5'] = 'ÜBERSPRUNGEN — keine events.db'
        return ctx

    findings: List[ForensicFinding] = []

    # Schritt 1: MACtime-Index aufbauen
    mactime_index = _build_mactime_index(ctx.events_db_path)
    log.info(f'  MACtime-Index: {len(mactime_index)} Dateien')

    # Schritt 2: Anomalie-Regeln anwenden
    findings += _check_macb_anomalies(mactime_index)
    findings += _check_activity_burst(ctx.events_db_path)
    findings += _check_staging_area(mactime_index)
    findings += _check_deleted_system_files(mactime_index)
    findings += _check_night_activity(mactime_index)

    # Schritt 3: Stage 9 Kreuzreferenz — Schwere hochstufen wenn bestätigt
    findings = _cross_reference_stage9(findings, ctx.antiforensics_hits)

    # Gruppe 6: Sorter-Mismatch (Dateiendung ≠ erkannter Typ)
    findings += _check_sorter_mismatches(ctx.tsk_sorter_files, mactime_index)

    # Schritt 4: CVE-Zeitfenster aus Stage 7
    findings += _check_cve_windows(ctx.iocs, ctx.events_db_path)

    # Schritt 5: Stage 6 Kontext für jeden Befund ergänzen
    for f in findings:
        if f.anomaly_time:
            f.evidence = _get_stage6_context(ctx.events_db_path, f.anomaly_time)

    # Nach Schwere sortieren
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    findings.sort(key=lambda f: order.get(f.severity, 3))

    ctx.forensic_findings = findings
    ctx.stage_status['stage_8.5'] = f'{len(findings)} Befunde'
    log.info(f'  {len(findings)} forensische Befunde gefunden')

    # JSON speichern
    if ctx.case_dir:
        _save_findings_json(findings, ctx.case_dir)

    return ctx


# ── Schritt 1: MACtime-Index ─────────────────────────────────────────────────

def _build_mactime_index(db_path: Path) -> Dict[str, Dict[str, Optional[datetime]]]:
    """Gruppiert MACtime-Events nach file_path und extrahiert M/A/C/B Timestamps."""
    index: Dict[str, Dict[str, Optional[datetime]]] = defaultdict(
        lambda: {'M': None, 'A': None, 'C': None, 'B': None}
    )
    try:
        with EventStore(db_path) as store:
            rows = store._conn.execute(
                "SELECT file_path, event_type, message, timestamp "
                "FROM events WHERE source = 'mactime' AND file_path IS NOT NULL"
            ).fetchall()

        for file_path, event_type, message, ts in rows:
            if not file_path:
                continue
            m = _MACB_RE.match(message or '')
            macb_str = m.group(1) if m else (event_type or '').replace('filesystem_', '')
            for flag, key in [('m', 'M'), ('a', 'A'), ('c', 'C'), ('b', 'B')]:
                if flag in macb_str:
                    existing = index[file_path][key]
                    if existing is None or (isinstance(ts, datetime) and ts < existing):
                        index[file_path][key] = ts if isinstance(ts, datetime) else None
    except Exception as e:
        log.warning(f'  MACtime-Index Fehler: {e}')
    return dict(index)


# ── Schritt 2: Anomalie-Regeln ───────────────────────────────────────────────

# Pfade bei denen M < B wirklich verdächtig ist (Staging/User-Bereich)
_MB_SUSPICIOUS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/home/', '/root/', '/run/user/']
# Pfade bei denen M < B fast immer dpkg/apt ist → ignorieren
_MB_TRUSTED    = ['/usr/', '/bin/', '/sbin/', '/lib/', '/usr/lib/',
                  '/usr/bin/', '/usr/sbin/', '/usr/share/']


def _check_macb_anomalies(index: Dict) -> List[ForensicFinding]:
    findings = []
    for fpath, ts in index.items():
        M, B, C = ts.get('M'), ts.get('B'), ts.get('C')

        # Regel: M < B (Modified vor Born)
        # Pfad-Heuristik: dpkg setzt mtime auf Build-Datum → in Systempfaden normal
        if M and B and M < B:
            in_suspicious = any(fpath.startswith(p) for p in _MB_SUSPICIOUS)
            in_trusted    = any(fpath.startswith(p) for p in _MB_TRUSTED)
            if in_suspicious:
                findings.append(ForensicFinding(
                    severity='CRITICAL',
                    rule='timestomping_M_lt_B',
                    file=fpath,
                    description=(
                        f'Modified ({M:%Y-%m-%d %H:%M}) liegt VOR Born ({B:%Y-%m-%d %H:%M}) '
                        f'in Verdachtspfad — Timestamp-Manipulation'
                    ),
                    anomaly_time=M,
                ))
            elif not in_trusted:
                # /opt/, /srv/, /var/ etc. — könnte rsync/tar sein, prüfenswert
                findings.append(ForensicFinding(
                    severity='HIGH',
                    rule='timestomping_M_lt_B',
                    file=fpath,
                    description=(
                        f'Modified ({M:%Y-%m-%d %H:%M}) liegt VOR Born ({B:%Y-%m-%d %H:%M}) '
                        f'— möglicherweise rsync/tar oder Manipulation'
                    ),
                    anomaly_time=M,
                ))
            # in_trusted (/usr/, /bin/ etc.) → dpkg-Verhalten → kein Finding

        # Regel: C >> M (ctime viel neuer als mtime → touch -t verwendet)
        if M and C and (C - M) > timedelta(hours=1):
            findings.append(ForensicFinding(
                severity='HIGH',
                rule='timestomping_C_gt_M',
                file=fpath,
                description=f'ctime ({C}) ist {(C-M).seconds//3600}h neuer als mtime ({M}) — touch -t Verdacht',
                anomaly_time=M,
            ))

        # Regel: Timestamp vor Jahr 2000
        for key, val in ts.items():
            if val and val.year < 2000:
                findings.append(ForensicFinding(
                    severity='HIGH',
                    rule='timestamp_before_2000',
                    file=fpath,
                    description=f'Timestamp {key}={val} liegt vor Jahr 2000 — unrealistisch',
                    anomaly_time=val,
                ))
                break

    return findings


def _check_activity_burst(db_path: Path) -> List[ForensicFinding]:
    """Erkennt viele Systemdatei-Modifikationen in kurzer Zeit."""
    findings = []
    try:
        with EventStore(db_path) as store:
            rows = store._conn.execute(
                "SELECT file_path, timestamp FROM events "
                "WHERE source = 'mactime' "
                "  AND event_type LIKE '%m%' "
                "  AND file_path IS NOT NULL "
                "ORDER BY timestamp"
            ).fetchall()

        # Nur Systemdateien
        system_mods = [
            (fp, ts) for fp, ts in rows
            if any(fp.startswith(p) for p in SYSTEM_PATHS)
            and isinstance(ts, datetime)
        ]

        # Sliding Window: >10 Dateien in 5 Minuten
        window = timedelta(minutes=5)
        for i, (fp, ts) in enumerate(system_mods):
            burst = [x for x in system_mods if ts <= x[1] <= ts + window]
            if len(burst) >= 10:
                paths = ', '.join(set(x[0] for x in burst[:5]))
                findings.append(ForensicFinding(
                    severity='HIGH',
                    rule='activity_burst_system_path',
                    file=fp,
                    description=f'{len(burst)} Systemdateien in 5 Min modifiziert: {paths}...',
                    anomaly_time=ts,
                ))
                break  # nur einmal pro Burst melden

    except Exception as e:
        log.warning(f'  Activity-Burst-Check Fehler: {e}')
    return findings


def _check_staging_area(index: Dict) -> List[ForensicFinding]:
    findings = []
    for fpath, ts in index.items():
        if any(fpath.startswith(p) for p in STAGING_PATHS):
            B = ts.get('B')
            findings.append(ForensicFinding(
                severity='MEDIUM',
                rule='staging_area',
                file=fpath,
                description=f'Datei in Staging-Bereich {fpath}',
                anomaly_time=B or ts.get('M'),
            ))
    return findings


def _check_deleted_system_files(index: Dict) -> List[ForensicFinding]:
    findings = []
    for fpath, ts in index.items():
        if fpath.startswith('* '):
            clean = fpath[2:]
            if any(clean.startswith(p) for p in SYSTEM_PATHS):
                findings.append(ForensicFinding(
                    severity='HIGH',
                    rule='deleted_system_file',
                    file=clean,
                    description=f'Systemdatei gelöscht: {clean}',
                    anomaly_time=ts.get('M') or ts.get('B'),
                ))
    return findings


def _check_night_activity(index: Dict) -> List[ForensicFinding]:
    findings = []
    seen_windows = set()
    for fpath, ts in index.items():
        M = ts.get('M')
        if M and 0 <= M.hour < 5:
            window_key = f'{M.date()}_{M.hour}'
            if window_key not in seen_windows and any(
                fpath.startswith(p) for p in SYSTEM_PATHS
            ):
                seen_windows.add(window_key)
                findings.append(ForensicFinding(
                    severity='MEDIUM',
                    rule='night_activity',
                    file=fpath,
                    description=f'Systemdatei-Aktivität um {M.strftime("%H:%M")} Uhr (Nachtzeit)',
                    anomaly_time=M,
                ))
    return findings


# ── Schritt 3: Stage 9 Kreuzreferenz ─────────────────────────────────────────

def _cross_reference_stage9(
    findings: List[ForensicFinding],
    antiforensics_hits: List[Dict]
) -> List[ForensicFinding]:
    """Stuft Schwere auf CRITICAL wenn Stage 9 denselben Befund bestätigt."""
    for finding in findings:
        for hit in antiforensics_hits:
            hit_file = hit.get('file', '')
            hit_type = hit.get('type', '')

            # Timestomping von Stage 9 bestätigt
            if (finding.rule.startswith('timestomping') and
                    hit_type == 'timestomping' and
                    (hit_file in finding.file or finding.file in hit_file)):
                finding.severity = 'CRITICAL'
                finding.description += f' [Stage 9 bestätigt: {hit.get("details","")[:80]}]'

            # Rootkit + Systemdatei modifiziert
            if (finding.rule in ('activity_burst_system_path', 'deleted_system_file') and
                    hit_type == 'rootkit_indicator'):
                finding.severity = 'CRITICAL'
                finding.description += ' [Rootkit-Indikator von Stage 9 bestätigt]'

    return findings


# ── Schritt 4: CVE-Zeitfenster ───────────────────────────────────────────────

def _check_cve_windows(iocs, db_path: Path) -> List[ForensicFinding]:
    findings = []
    cves = [ioc for ioc in iocs if ioc.type == 'cve']
    if not cves:
        return findings

    try:
        with EventStore(db_path) as store:
            system_mods = store._conn.execute(
                "SELECT file_path, timestamp FROM events "
                "WHERE source = 'mactime' AND event_type LIKE '%m%' "
                "  AND file_path IS NOT NULL"
            ).fetchall()

        window = timedelta(minutes=30)
        for cve_ioc in cves:
            if not cve_ioc.timestamp:
                continue
            cve_ts = cve_ioc.timestamp
            nearby = [
                (fp, ts) for fp, ts in system_mods
                if isinstance(ts, datetime) and
                abs((ts - cve_ts).total_seconds()) <= window.total_seconds() and
                any(fp.startswith(p) for p in SYSTEM_PATHS)
            ]
            if nearby:
                files = ', '.join(set(fp for fp, _ in nearby[:3]))
                findings.append(ForensicFinding(
                    severity='CRITICAL' if 'CVE-2021-4034' in cve_ioc.value
                             or 'CVE-2022-0847' in cve_ioc.value else 'HIGH',
                    rule='cve_time_window',
                    file=files,
                    description=(
                        f'{cve_ioc.value} um {cve_ts.strftime("%H:%M")} gefunden — '
                        f'{len(nearby)} Systemdateien ±30 Min modifiziert: {files}'
                    ),
                    anomaly_time=cve_ts,
                ))
    except Exception as e:
        log.warning(f'  CVE-Window-Check Fehler: {e}')
    return findings


# ── Schritt 5: Stage 6 Kontext ───────────────────────────────────────────────

def _get_stage6_context(
    db_path: Path,
    anomaly_time: datetime,
    window_minutes: int = 10
) -> List[Dict]:
    context = []
    window = timedelta(minutes=window_minutes)
    try:
        with EventStore(db_path) as store:
            rows = store._conn.execute(
                "SELECT timestamp, source, message, username, ip FROM events "
                "WHERE source != 'mactime' "
                "  AND source != 'text_fallback' "
                "  AND timestamp BETWEEN ? AND ? "
                "ORDER BY timestamp "
                "LIMIT 20",
                [anomaly_time - window, anomaly_time + window]
            ).fetchall()
        for ts, src, msg, user, ip in rows:
            context.append({
                'time':    ts.strftime('%H:%M:%S') if isinstance(ts, datetime) else str(ts),
                'source':  src,
                'message': (msg or '')[:120],
                'user':    user,
                'ip':      ip,
            })
    except Exception as e:
        log.warning(f'  Stage-6-Kontext Fehler: {e}')
    return context


# ── Gruppe 6: Sorter-Mismatch ────────────────────────────────────────────────

def _check_sorter_mismatches(
    sorter_files: Dict[str, str],
    mactime_index: Dict
) -> List[ForensicFinding]:
    """Erkennt Dateien deren Typ nicht zur Dateiendung passt."""
    findings = []
    if not sorter_files:
        return findings

    # MACtime-Anomalie-Dateien für Kreuzprüfung sammeln
    mactime_anomaly_files = {
        Path(fpath).name for fpath, ts in mactime_index.items()
        if ts.get('M') and ts.get('B') and ts['M'] < ts['B']
    }

    for filename, detected_category in sorter_files.items():
        ext = Path(filename).suffix.lower()
        expected = EXT_EXPECTED.get(ext)

        # Regel 1: Dateiendung passt nicht zur erkannten Kategorie
        if expected and expected != detected_category:
            severity = 'CRITICAL' if detected_category == 'exec' else 'HIGH'
            description = (
                f'Dateiendung {ext} (erwartet: {expected}) '
                f'aber Sorter erkannte: {detected_category} — mögliche Tarnung'
            )
            # Doppelte Verschleierung: Mismatch + MACtime-Anomalie auf gleicher Datei
            if filename in mactime_anomaly_files:
                severity = 'CRITICAL'
                description += ' + MACtime-Timestamp-Anomalie — doppelte Verschleierung!'

            findings.append(ForensicFinding(
                severity=severity,
                rule='sorter_extension_mismatch',
                file=filename,
                description=description,
                anomaly_time=None,
            ))

        # Regel 2: Executable in Staging-Area
        if detected_category == 'exec':
            for staging in STAGING_PATHS:
                if staging.strip('/') in filename.lower():
                    findings.append(ForensicFinding(
                        severity='CRITICAL',
                        rule='sorter_exec_in_staging',
                        file=filename,
                        description=f'Executable in Staging-Bereich: {filename}',
                        anomaly_time=None,
                    ))
                    break

    return findings


# ── JSON Export ───────────────────────────────────────────────────────────────

def _save_findings_json(findings: List[ForensicFinding], case_dir: Path) -> None:
    out = case_dir / 'forensic_findings.json'
    data = []
    for f in findings:
        data.append({
            'severity':     f.severity,
            'rule':         f.rule,
            'file':         f.file,
            'description':  f.description,
            'anomaly_time': f.anomaly_time.isoformat() if f.anomaly_time else None,
            'evidence':     f.evidence,
        })
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    log.info(f'  forensic_findings.json → {out}')
