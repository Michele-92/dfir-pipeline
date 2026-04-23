from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict


@dataclass
class CoCEntry:
    stage:     str
    action:    str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ChainOfCustody:
    file_name:  str
    sha256:     str
    md5:        str
    size_gb:    float
    start_time: datetime
    entries:    List[CoCEntry] = field(default_factory=list)

    def add_entry(self, stage: str, action: str) -> None:
        self.entries.append(CoCEntry(stage=stage, action=action))
