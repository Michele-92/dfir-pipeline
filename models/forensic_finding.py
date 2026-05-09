from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class ForensicFinding:
    severity:     str            # CRITICAL / HIGH / MEDIUM
    rule:         str            # Regelname der getriggert hat
    file:         str            # betroffene Datei
    description:  str            # menschenlesbare Beschreibung
    anomaly_time: Optional[datetime] = None
    evidence:     List[Dict[str, Any]] = field(default_factory=list)
