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
    """Pipeline-Ausführungsprotokoll — dokumentiert alle Analyse-Schritte.
    Hinweis: Dies ist ein Teil der übergeordneten forensischen Chain of Custody,
    nicht die CoC selbst. Die CoC umfasst alle Maßnahmen vor, während und nach
    der Pipeline-Ausführung."""
    file_name:  str
    sha256:     str
    md5:        str
    size_gb:    float
    start_time: datetime
    entries:               List[CoCEntry]      = field(default_factory=list)
    extracted_file_hashes: Dict[str, str]      = field(default_factory=dict)

    def add_entry(self, stage: str, action: str) -> None:
        self.entries.append(CoCEntry(stage=stage, action=action))

    def add_file_hash(self, filename: str, sha256: str) -> None:
        self.extracted_file_hashes[filename] = sha256
