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
