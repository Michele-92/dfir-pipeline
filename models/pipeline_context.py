from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from .event import ForensicEvent
from .ioc import IOC
from .chain_of_custody import ChainOfCustody
from .forensic_finding import ForensicFinding


@dataclass
class PipelineContext:
    # ── Eingabe ──────────────────────────────────────────
    disk_image_path:    Optional[Path] = None
    ram_dump_path:      Optional[Path] = None
    logs_dir_path:      Optional[Path] = None
    output_dir:         Path           = field(default_factory=lambda: Path('./output'))
    case_dir:           Optional[Path] = None

    # ── Stage 1: Dateierkennung ───────────────────────────
    file_type:          str   = ''
    file_size_gb:       float = 0.0
    sha256:             str   = ''
    md5:                str   = ''

    # ── Stage 2: Memory ───────────────────────────────────
    memory_results:     Dict[str, Any] = field(default_factory=dict)

    # ── Stage 3: System-Profiling ─────────────────────────
    os_family:          str  = ''
    os_name:            str  = ''
    kernel_version:     str  = ''
    hostname:           str  = ''
    timezone:           str  = 'UTC'
    log_paths:          Dict[str, Path] = field(default_factory=dict)

    # ── Performance ───────────────────────────────────────
    workers:             int  = 2
    skip_bulk_extractor: bool = False
    skip_mactime:        bool = False

    # ── Stage 4: Disk ─────────────────────────────────────
    disk_artifacts:     Dict[str, Any] = field(default_factory=dict)
    image_count:        int  = 0
    email_db_found:     bool = False
    encrypted_count:    int  = 0
    unknown_ext_count:  int  = 0
    dissect_empty:      bool = False

    # ── Stage 4.1: Autopsy ────────────────────────────────
    autopsy_ran:        bool = False
    autopsy_reason:     str  = ''
    autopsy_results:    Dict[str, Any] = field(default_factory=dict)

    # ── Stage 5: TSK Fallback ─────────────────────────────
    tsk_fallback_used:       bool           = False
    tsk_results:             Dict[str, Any] = field(default_factory=dict)
    tsk_partitions:            List[dict]     = field(default_factory=list)
    tsk_log_files_extracted:   int            = 0
    tsk_deleted_found:         int            = 0
    tsk_deleted_recovered:     int            = 0
    tsk_deleted_not_recovered: int            = 0
    tsk_extracted_filenames:   List[str]      = field(default_factory=list)
    tsk_mactime_events:        int            = 0
    tsk_mactime_file:          str            = ''
    tsk_sorter_ran:            bool           = False
    tsk_sorter_categories:     Dict[str, int] = field(default_factory=dict)

    # ── Stage 6: Log-Parsing ─────────────────────────────
    events:             List[ForensicEvent] = field(default_factory=list)
    events_db_path:     Optional[Path]      = None
    parser_stats:       Dict[str, int]      = field(default_factory=dict)
    parser_file_map:    Dict[str, dict]     = field(default_factory=dict)
    all_parser_names:   List[str]           = field(default_factory=list)
    total_log_lines:    int = 0
    parsed_events:      int = 0
    hayabusa_hits:      int = 0

    # ── Stage 7: IOC-Extraktion ───────────────────────────
    iocs:                   List[IOC] = field(default_factory=list)
    ioc_quality:            str  = 'HOCH'
    bulk_extractor_ran:     bool = False
    bulk_extractor_iocs:    int  = 0

    # ── Stage 8: Normalisierung ───────────────────────────
    normalized_events:  List[ForensicEvent] = field(default_factory=list)
    timezone_offset:    str = ''   # z.B. 'UTC+1' oder 'UTC-5'
    earliest_event:     str = ''   # frühestes Event UTC + Lokalzeit
    latest_event:       str = ''   # letztes Event UTC + Lokalzeit

    # ── Stage 9: Anti-Forensics ───────────────────────────
    antiforensics_hits: List[Dict] = field(default_factory=list)

    # ── Stage 8.5: Forensischer Analyse-Algorithmus ───────
    forensic_findings:  List[ForensicFinding] = field(default_factory=list)

    # ── Stage 10: ML ──────────────────────────────────────
    anomalies:          List[ForensicEvent] = field(default_factory=list)
    anomaly_scores:     List[float]         = field(default_factory=list)

    # ── Stage 11: MITRE ───────────────────────────────────
    mitre_hits:         List[Dict] = field(default_factory=list)

    # ── Stage 12: Ergebnis-Aggregation ────────────────────
    enriched_summary:   str = ''

    # ── Stage 13: Qualität ────────────────────────────────
    stage_errors:       Dict[str, str] = field(default_factory=dict)
    stage_status:       Dict[str, str] = field(default_factory=dict)

    # ── Chain of Custody ──────────────────────────────────
    coc:                Optional[ChainOfCustody] = None
    start_time:         datetime = field(default_factory=datetime.now)
