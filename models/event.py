from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


@dataclass
class ForensicEvent:
    timestamp:     datetime
    source:        str
    event_type:    str
    message:       str
    user:          Optional[str]  = None
    ip:            Optional[str]  = None
    process:       Optional[str]  = None
    file_path:     Optional[str]  = None
    severity:      str            = 'info'
    anomaly_score: float          = 0.0
    mitre_tags:    List[str]      = field(default_factory=list)
    # ── Provenienz (Review-Architekturpunkt #7) ───────────────
    orig_path:     str            = ''   # Pfad auf dem Image (/var/log/auth.log)
    source_file:   str            = ''   # extrahierte Datei (log_artefakte/p2048/...)
    partition:     str            = ''   # z.B. 'Partition 2 (offset 2048)'
    parser_name:   str            = ''   # Parser der das Event erzeugt hat
    extraction:    str            = ''   # tsk_icat | tsk_recover | logs_dir
