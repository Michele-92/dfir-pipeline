"""
utils/reexport.py — Reexport-Modus: Stage 14 aus gespeichertem Snapshot neu ausführen.

Ablauf:
  1. save_ctx_snapshot()       → wird am Ende jedes normalen Durchlaufs aufgerufen
  2. list_available_runs()     → zeigt alle Case-Ordner mit Snapshot
  3. create_reexport_dir()     → kopiert Quell-Ordner ohne Stage-14-Dokumente
  4. reconstruct_ctx()         → baut PipelineContext aus Snapshot neu auf
  5. pipeline.py ruft Stage 14 → Stage 14 merkt keinen Unterschied
"""

import json
import shutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

from models.pipeline_context import PipelineContext
from models.chain_of_custody import ChainOfCustody, CoCEntry
from models.ioc import IOC
from models.forensic_finding import ForensicFinding
from models.event import ForensicEvent

log = logging.getLogger(__name__)

_SNAPSHOT_FILE    = 'ctx_snapshot.json'
_SNAPSHOT_VERSION = 1


def _sanitize(obj):
    """
    Ersetzt ungueltige Surrogate-Zeichen rekursiv in allen Strings.
    Surrogate entstehen wenn Python Dateien mit ungueltigem UTF-8 liest
    (z.B. binary Logs, beschaedigte Configs).
    json.dumps kann sie nicht serialisieren - hier bereinigen.
    """
    if isinstance(obj, str):
        return obj.encode('utf-8', errors='replace').decode('utf-8')
    if isinstance(obj, dict):
        return {_sanitize(k): _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(i) for i in obj]
    return obj

# Dateien die Stage 14 generiert → beim Reexport-Kopieren weglassen
_GENERATED_DOCS = {
    'report.pdf',
    'chain_of_custody.pdf',
    'forensic_findings.csv',
    'forensic_findings.xlsx',
    'activity_timeline.csv',
    'login_events.csv',
    'system_reboots.csv',
    'system_crashes.csv',
    'filesystem_timeline.csv',
    'filtered_filesystem_timeline.xlsx',
    'reboot_sessions.xlsx',
    'ip_sessions.xlsx',
    'pipeline_report.json',
    'autopsy_status.json',
    'iocs.json',
    'antiforensics.json',
    'DFIR_Critical_Report.pdf',
}


# ── 1. SNAPSHOT SPEICHERN ────────────────────────────────────────────────────

def save_ctx_snapshot(ctx: PipelineContext, case_dir: Path) -> None:
    """Speichert alles was Stage 14 braucht als ctx_snapshot.json im Case-Ordner."""

    # Nur top 200 critical/high/medium Events für PDF-Timeline
    relevant = [
        e for e in ctx.normalized_events
        if getattr(e, 'severity', '') in ('critical', 'high', 'medium')
    ]
    relevant.sort(key=lambda e: e.timestamp)
    top_events = relevant[:200]

    snapshot = {
        '_snapshot_version': _SNAPSHOT_VERSION,
        '_created':          datetime.now(timezone.utc).isoformat(),
        '_source_case':      case_dir.name,

        # ── Basis ───────────────────────────────────────────
        'start_time':      ctx.start_time.isoformat(),
        'disk_image_path': str(ctx.disk_image_path) if ctx.disk_image_path else None,
        'ram_dump_path':   str(ctx.ram_dump_path)   if ctx.ram_dump_path   else None,
        'sha256':          ctx.sha256,
        'sha1':            getattr(ctx, 'sha1', ''),
        'md5':             ctx.md5,
        'file_size_gb':    ctx.file_size_gb,
        'file_type':       ctx.file_type,
        'hash_source':     ctx.hash_source,
        'combined_case':   getattr(ctx, 'combined_case', False),
        'evidence_items':  getattr(ctx, 'evidence_items', []),

        # ── System-Profil ────────────────────────────────────
        'os_family':        ctx.os_family,
        'os_name':          ctx.os_name,
        'kernel_version':   ctx.kernel_version,
        'hostname':         ctx.hostname,
        'timezone':         ctx.timezone,
        'timezone_display': ctx.timezone_display,
        'ip_addresses':     ctx.ip_addresses,

        # ── Statistiken ──────────────────────────────────────
        'total_log_lines': ctx.total_log_lines,
        'parsed_events':   ctx.parsed_events,
        'ioc_quality':     ctx.ioc_quality,
        'stage_status':    ctx.stage_status,

        # ── Tools / Flags ────────────────────────────────────
        'tsk_fallback_used': ctx.tsk_fallback_used,
        'autopsy_ran':       ctx.autopsy_ran,
        'autopsy_reason':    ctx.autopsy_reason,
        'autopsy_results':   ctx.autopsy_results,

        # ── Kernel / Anti-Forensics ──────────────────────────
        'all_kernel_versions':     ctx.all_kernel_versions,
        'loaded_kernel_from_logs': ctx.loaded_kernel_from_logs,
        'reboot_pending':          ctx.reboot_pending,
        'grub_config':             ctx.grub_config,
        'swap_config':             ctx.swap_config,
        'kernel_compile_flags':    ctx.kernel_compile_flags,
        'primary_symlinks':        ctx.primary_symlinks,
        'rc_local_content':        ctx.rc_local_content,

        # ── Partitionen ──────────────────────────────────────
        'partition_profiles':  ctx.partition_profiles,
        'tsk_partitions':      ctx.tsk_partitions,
        'analysis_partitions': ctx.analysis_partitions,
        'partition_layout':    ctx.partition_layout,

        # ── Sorter ────────────────────────────────────────────
        'tsk_sorter_files':      getattr(ctx, 'tsk_sorter_files',      {}),
        'tsk_sorter_categories': getattr(ctx, 'tsk_sorter_categories', {}),
        'tsk_sorter_ran':        getattr(ctx, 'tsk_sorter_ran',        False),

        # ── Nutzer ───────────────────────────────────────────
        'users': ctx.users,

        # ── Basic Checks ─────────────────────────────────────
        'basic_checks':          ctx.basic_checks,
        'basic_check_anomalies': ctx.basic_check_anomalies,

        # ── E01-Hashes (optional) ────────────────────────────
        'e01_hash': getattr(ctx, 'e01_hash', None),
        'e01_md5':  getattr(ctx, 'e01_md5',  None),

        # ── IOCs ─────────────────────────────────────────────
        'iocs': [
            {
                'type':      ioc.type,
                'value':     ioc.value,
                'source':    ioc.source,
                'context':   ioc.context,
                'timestamp': ioc.timestamp.isoformat() if ioc.timestamp else None,
            }
            for ioc in ctx.iocs
        ],

        # ── MITRE / ML (aktuell leer) ────────────────────────
        'mitre_hits': ctx.mitre_hits,
        'anomalies':  [],

        # ── Anti-Forensics ───────────────────────────────────
        'antiforensics_hits': ctx.antiforensics_hits,

        # ── Forensic Findings (Stage 8.5) ────────────────────
        'forensic_findings': [
            {
                'severity':      f.severity,
                'rule':          f.rule,
                'file':          f.file,
                'description':   f.description,
                'anomaly_time':  f.anomaly_time.isoformat() if f.anomaly_time else None,
                'evidence':      f.evidence or [],
                'expected_type': f.expected_type,
                'detected_type': f.detected_type,
            }
            for f in ctx.forensic_findings
        ],

        # ── Top Events für PDF (max 200) ─────────────────────
        'top_events_for_pdf': [
            {
                'severity':   getattr(e, 'severity', 'info'),
                'timestamp':  e.timestamp.isoformat(),
                'message':    e.message[:300],
                'source':     e.source,
                'event_type': getattr(e, 'event_type', '') or '',
                'user':       getattr(e, 'user',       '') or '',
                'ip':         getattr(e, 'ip',         '') or '',
            }
            for e in top_events
        ],

        # ── Chain of Custody ─────────────────────────────────
        'coc': {
            'file_name':  ctx.coc.file_name,
            'sha256':     ctx.coc.sha256,
            'sha1':       ctx.coc.sha1,
            'md5':        ctx.coc.md5,
            'size_gb':    ctx.coc.size_gb,
            'start_time': ctx.coc.start_time.isoformat(),
            'entries': [
                {
                    'stage':     e.stage,
                    'action':    e.action,
                    'timestamp': e.timestamp.isoformat(),
                }
                for e in ctx.coc.entries
            ],
            'extracted_file_hashes': ctx.coc.extracted_file_hashes,
            'evidence_hashes':       getattr(ctx.coc, 'evidence_hashes', {}),
        } if ctx.coc else None,
    }

    out = case_dir / _SNAPSHOT_FILE
    out.write_text(
        json.dumps(_sanitize(snapshot), indent=2, ensure_ascii=False, default=str),
        encoding='utf-8',
    )
    log.info(f'  ctx_snapshot.json → {out}')


# ── 2. VORHANDENE TESTLÄUFE AUFLISTEN ────────────────────────────────────────

def list_available_runs(output_dir: Path) -> List[Dict]:
    """
    Gibt alle Case-Verzeichnisse zurueck die einen Snapshot haben (neueste zuerst).
    Sucht rekursiv — case_dir liegt 3 Ebenen tief:
      output_dir / YYYY / MM_Monat / DD_Tag / case_YYYYMMDD_HHMMSS / ctx_snapshot.json
    """
    runs = []
    if not output_dir.exists():
        return runs

    # rglob findet ctx_snapshot.json auf beliebiger Tiefe
    snap_paths = sorted(
        output_dir.rglob(_SNAPSHOT_FILE),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for snap_path in snap_paths:
        d = snap_path.parent   # das eigentliche case_dir
        try:
            snap = json.loads(snap_path.read_text(encoding='utf-8'))
            if not snap:          # leere Datei vom alten Crash
                continue
            runs.append({
                'dir':      d,
                'name':     d.name,
                'created':  snap.get('_created', '?')[:19].replace('T', ' '),
                'os':       snap.get('os_name', '?') or '?',
                'hostname': snap.get('hostname', '?') or '?',
                'findings': len(snap.get('forensic_findings', [])),
                'iocs':     len(snap.get('iocs', [])),
            })
        except Exception:
            continue
    return runs


# ── 3. REEXPORT-ORDNER ERSTELLEN ─────────────────────────────────────────────

def create_reexport_dir(source_dir: Path, output_dir: Path) -> Path:
    """
    Erstellt einen neuen Case-Ordner der den Quellordner widerspiegelt,
    aber ohne die von Stage 14 generierten Dokumente.
    Name: <Quellname>_(Testdaten_von_YYYY-MM-DD_HH-MM)
    """
    date_str = datetime.now().strftime('%Y-%m-%d_%H-%M')
    new_name = f'{source_dir.name}_(Testdaten_von_{date_str})'
    new_dir  = output_dir / new_name
    new_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    for f in source_dir.iterdir():
        if f.is_file() and f.name not in _GENERATED_DOCS:
            shutil.copy2(f, new_dir / f.name)
            copied += 1

    log.info(f'  Reexport-Ordner erstellt: {new_dir}  ({copied} Dateien kopiert)')
    return new_dir


# ── 4. CTX AUS SNAPSHOT REKONSTRUIEREN ───────────────────────────────────────

def reconstruct_ctx(snapshot_path: Path, new_case_dir: Path) -> PipelineContext:
    """
    Lädt ctx_snapshot.json und baut einen vollständigen PipelineContext für Stage 14.
    Stage 14 bekommt diesen ctx — merkt keinen Unterschied zum echten Durchlauf.
    """
    data = json.loads(snapshot_path.read_text(encoding='utf-8'))

    # IOCs
    iocs: List[IOC] = []
    for d in data.get('iocs', []):
        iocs.append(IOC(
            type=d['type'], value=d['value'],
            source=d['source'], context=d['context'],
            timestamp=datetime.fromisoformat(d['timestamp']) if d.get('timestamp') else None,
        ))

    # Forensic Findings
    findings: List[ForensicFinding] = []
    for d in data.get('forensic_findings', []):
        findings.append(ForensicFinding(
            severity=d['severity'], rule=d['rule'],
            file=d['file'], description=d['description'],
            anomaly_time=datetime.fromisoformat(d['anomaly_time']) if d.get('anomaly_time') else None,
            evidence=d.get('evidence', []),
            expected_type=d.get('expected_type'),
            detected_type=d.get('detected_type'),
        ))

    # Top Events für PDF (rekonstruiert als ForensicEvent)
    top_events: List[ForensicEvent] = []
    for d in data.get('top_events_for_pdf', []):
        top_events.append(ForensicEvent(
            timestamp  = datetime.fromisoformat(d['timestamp']),
            source     = d['source'],
            event_type = d.get('event_type', ''),
            message    = d['message'],
            severity   = d.get('severity', 'info'),
            user       = d.get('user') or None,
            ip         = d.get('ip')   or None,
        ))

    # Chain of Custody
    coc: Optional[ChainOfCustody] = None
    coc_data = data.get('coc')
    if coc_data:
        coc = ChainOfCustody(
            file_name  = coc_data['file_name'],
            sha256     = coc_data['sha256'],
            sha1       = coc_data.get('sha1', ''),
            md5        = coc_data['md5'],
            size_gb    = coc_data['size_gb'],
            start_time = datetime.fromisoformat(coc_data['start_time']),
        )
        for e in coc_data.get('entries', []):
            entry           = CoCEntry(stage=e['stage'], action=e['action'])
            entry.timestamp = datetime.fromisoformat(e['timestamp'])
            coc.entries.append(entry)
        coc.extracted_file_hashes = coc_data.get('extracted_file_hashes', {})
        coc.evidence_hashes       = coc_data.get('evidence_hashes', {})
        # Reexport-Eintrag hinzufügen
        coc.add_entry('reexport', f'Dokumente neu erstellt aus Snapshot — {new_case_dir.name}')

    ctx = PipelineContext(
        disk_image_path  = Path(data['disk_image_path']) if data.get('disk_image_path') else None,
        ram_dump_path    = Path(data['ram_dump_path'])   if data.get('ram_dump_path')   else None,
        output_dir       = new_case_dir.parent,
        case_dir         = new_case_dir,

        file_type        = data.get('file_type', ''),
        file_size_gb     = data.get('file_size_gb', 0.0),
        sha256           = data.get('sha256', ''),
        sha1             = data.get('sha1', ''),
        md5              = data.get('md5', ''),
        hash_source      = data.get('hash_source', 'Snapshot'),

        os_family        = data.get('os_family', ''),
        os_name          = data.get('os_name', ''),
        kernel_version   = data.get('kernel_version', ''),
        hostname         = data.get('hostname', ''),
        timezone         = data.get('timezone', 'UTC'),
        timezone_display = data.get('timezone_display', ''),
        ip_addresses     = data.get('ip_addresses', []),

        total_log_lines  = data.get('total_log_lines', 0),
        parsed_events    = data.get('parsed_events', 0),
        ioc_quality      = data.get('ioc_quality', ''),
        stage_status     = data.get('stage_status', {}),

        tsk_fallback_used = data.get('tsk_fallback_used', False),
        autopsy_ran       = data.get('autopsy_ran', False),
        autopsy_reason    = data.get('autopsy_reason', ''),
        autopsy_results   = data.get('autopsy_results', {}),

        all_kernel_versions     = data.get('all_kernel_versions', []),
        loaded_kernel_from_logs = data.get('loaded_kernel_from_logs', ''),
        reboot_pending          = data.get('reboot_pending', False),
        grub_config             = data.get('grub_config', {}),
        swap_config             = data.get('swap_config', {}),
        kernel_compile_flags    = data.get('kernel_compile_flags', {}),
        primary_symlinks        = data.get('primary_symlinks', {}),
        rc_local_content        = data.get('rc_local_content', ''),

        combined_case       = data.get('combined_case', False),
        evidence_items      = data.get('evidence_items', []),
        partition_profiles  = data.get('partition_profiles', []),
        tsk_partitions      = data.get('tsk_partitions', []),
        analysis_partitions = data.get('analysis_partitions', []),
        partition_layout    = data.get('partition_layout', []),

        users = data.get('users', []),

        basic_checks          = data.get('basic_checks', []),
        basic_check_anomalies = data.get('basic_check_anomalies', 0),

        iocs               = iocs,
        mitre_hits         = data.get('mitre_hits', []),
        antiforensics_hits = data.get('antiforensics_hits', []),
        anomalies          = [],
        forensic_findings  = findings,
        normalized_events  = top_events,

        coc        = coc,
        start_time = datetime.fromisoformat(data['start_time']) if data.get('start_time') else datetime.now(),

        events_db_path = new_case_dir / 'events.db',
    )

    # Optionale E01-Attribute
    if data.get('e01_hash'):
        ctx.e01_hash = data['e01_hash']
    if data.get('e01_md5'):
        ctx.e01_md5 = data['e01_md5']

    # Sorter-Daten (dynamische Attribute — nicht im Dataclass-Schema)
    ctx.tsk_sorter_files      = data.get('tsk_sorter_files', {})
    ctx.tsk_sorter_categories = data.get('tsk_sorter_categories', {})
    ctx.tsk_sorter_ran        = data.get('tsk_sorter_ran', False)

    return ctx
