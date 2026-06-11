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
    sha1:       str = ''
    entries:               List[CoCEntry]      = field(default_factory=list)
    extracted_file_hashes: Dict[str, str]      = field(default_factory=dict)
    # Fall-Modus: Hashes pro Image — duerfen forensisch NIE vermischt werden
    evidence_hashes:       Dict[str, dict]     = field(default_factory=dict)

    def add_entry(self, stage: str, action: str) -> None:
        self.entries.append(CoCEntry(stage=stage, action=action))

    def add_evidence(self, name: str, md5: str = '', sha1: str = '',
                     sha256: str = '', size_gb: float = 0.0,
                     hash_source: str = '') -> None:
        self.evidence_hashes[name] = {
            'md5': md5, 'sha1': sha1, 'sha256': sha256,
            'size_gb': size_gb, 'hash_source': hash_source,
        }

    def add_file_hash(self, filename: str, sha256: str, md5: str = '') -> None:
        # Wert ist ein Dict (sha256 + md5) — Review-Fix #19: MD5 wurde
        # frueher berechnet und verworfen, Key war kollisionsanfaelliger Basename
        self.extracted_file_hashes[filename] = {'sha256': sha256, 'md5': md5}
