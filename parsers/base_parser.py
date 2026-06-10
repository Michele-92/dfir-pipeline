from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone
import logging
import re

from models.event import ForensicEvent

log = logging.getLogger(__name__)


class BaseParser(ABC):
    name:          str       = ''
    file_patterns: List[str] = []
    binary:        bool      = False
    # Systemzeitzone des analysierten Images (Stage 03) — wird von
    # route_and_parse vor dem Parsen gesetzt. Naive Log-Zeiten werden als
    # DIESE Zone interpretiert (Review-Fix CRITICAL #6: vorher doppelte
    # Konversion — Parser nahmen UTC an, Stage 08 verschob nochmal).
    system_tz:     str       = 'UTC'

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        pass

    @abstractmethod
    def parse(self, file_path: Path) -> List[ForensicEvent]:
        pass

    def safe_parse(self, file_path: Path) -> List[ForensicEvent]:
        try:
            return self.parse(file_path)
        except Exception as e:
            log.warning(f'Parser {self.name} fehlgeschlagen für {file_path}: {e}')
            return []

    def make_event(self, timestamp, source, event_type, message,
                   user=None, ip=None, process=None,
                   file_path=None, severity='info', **_) -> ForensicEvent:
        from utils.timestamp import to_utc
        ts = to_utc(timestamp, self.system_tz)
        if ts is None:
            # unparsebarer Timestamp: Event behalten (kein Beweisverlust),
            # aber klar kennzeichnen und auf Epoch setzen (filterbar)
            ts = datetime(1970, 1, 1, tzinfo=timezone.utc)
            event_type = f'{event_type}_ts_invalid'
        return ForensicEvent(
            timestamp   = ts,
            source      = source,
            event_type  = event_type,
            message     = message,
            user        = user,
            ip          = ip,
            process     = process,
            file_path   = str(file_path) if file_path else None,
            severity    = severity,
        )

    def read_lines(self, path: Path) -> List[str]:
        # gzip transparent lesen — rotierte Logs (.gz) fuer ALLE Parser
        if path.suffix == '.gz':
            import gzip
            try:
                with gzip.open(path, 'rt', errors='replace') as f:
                    return f.read().splitlines()
            except (OSError, EOFError):
                return []
        for enc in ['utf-8', 'latin-1', 'cp1252']:
            try:
                return path.read_text(encoding=enc).splitlines()
            except (UnicodeDecodeError, PermissionError):
                continue
        return []
