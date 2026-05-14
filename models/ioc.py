from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class IOC:
    type:      str
    value:     str
    source:    str
    context:   str
    timestamp: Optional[datetime] = None
