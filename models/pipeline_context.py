from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from .event import ForensicEvent
from .ioc import IOC
from .chain_of_custody import ChainOfCustody


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

    # ── Stage 2.5: System-Profiling ───────────────────────
    os_family:          str  = ''
    os_name:            str  = ''
    kernel_version:     str  = ''
    hostname:           str  = ''
    timezone:           str  = 'UTC'
    log_paths:          Dict[str, Path] = field(default_factory=dict)

    # ── Stage 3: Log-Parsing ──────────────────────────────
    events:             List[ForensicEvent] = field(default_factory=list)
    total_log_lines:    int = 0
    parsed_events:      int = 0

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

    # ── Stage 4.5: IOC-Extraktion ─────────────────────────
    iocs:               List[IOC] = field(default_factory=list)
    ioc_quality:        str = 'HOCH'

    # ── Stage 5: TSK Fallback ─────────────────────────────
    tsk_fallback_used:  bool = False
    tsk_results:        Dict[str, Any] = field(default_factory=dict)

    # ── Stage 6: Normalisierung ───────────────────────────
    normalized_events:  List[ForensicEvent] = field(default_factory=list)

    # ── Stage 7: Anti-Forensics ───────────────────────────
    antiforensics_hits: List[Dict] = field(default_factory=list)

    # ── Stage 8: ML ───────────────────────────────────────
    anomalies:          List[ForensicEvent] = field(default_factory=list)
    anomaly_scores:     List[float]         = field(default_factory=list)

    # ── Stage 9: MITRE ────────────────────────────────────
    mitre_hits:         List[Dict] = field(default_factory=list)

    # ── Stage 10: KI ──────────────────────────────────────
    enriched_summary:   str = ''

    # ── Stage 11: Qualität ────────────────────────────────
    stage_errors:       Dict[str, str] = field(default_factory=dict)
    stage_status:       Dict[str, str] = field(default_factory=dict)

    # ── Chain of Custody ──────────────────────────────────
    coc:                Optional[ChainOfCustody] = None
    start_time:         datetime = field(default_factory=datetime.now)
