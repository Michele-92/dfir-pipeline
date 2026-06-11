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

    # Max. Bytes pro Textdatei — OOM-Schutz: grosse Binaerdateien
    # (Journal, Datenbanken) rissen sonst den Worker-Prozess und damit
    # den gesamten ProcessPool (105 'fehler'-Dateien im Praxistest).
    MAX_READ_BYTES = 50 * 1024 * 1024    # 50 MB (Worker laufen parallel!)
    # Max. Zeilen — Binaerdaten mit vielen 0x0A-Bytes erzeugen sonst
    # Millionen Pseudo-Zeilen (Listen-Overhead > Dateigroesse)
    MAX_LINES      = 1_000_000

    def read_lines(self, path: Path) -> List[str]:
        # gzip transparent lesen — rotierte Logs (.gz) fuer ALLE Parser
        if path.suffix == '.gz':
            import gzip
            try:
                with gzip.open(path, 'rb') as f:
                    # 1 Byte mehr lesen als der Deckel: ist es da, wissen
                    # wir dass gekappt wurde (entpackte Groesse ist vorab
                    # nicht bekannt) -> Warnung statt stiller Kappung
                    data = f.read(self.MAX_READ_BYTES + 1)
            except (OSError, EOFError):
                return []
            if len(data) > self.MAX_READ_BYTES:
                log.warning(f'{path.name}: entpackt > '
                            f'{self.MAX_READ_BYTES/1e6:.0f} MB — nur erste '
                            f'{self.MAX_READ_BYTES/1e6:.0f} MB gelesen (OOM-Schutz)')
                data = data[:self.MAX_READ_BYTES]
            return self._bounded_lines(data)
        try:
            size = path.stat().st_size
            with path.open('rb') as f:
                data = f.read(min(size, self.MAX_READ_BYTES))
            if size > self.MAX_READ_BYTES:
                log.warning(f'{path.name}: {size/1e6:.0f} MB — nur erste '
                            f'{self.MAX_READ_BYTES/1e6:.0f} MB gelesen (OOM-Schutz)')
        except (OSError, PermissionError):
            return []
        return self._bounded_lines(data)

    def _bounded_lines(self, data: bytes) -> List[str]:
        text = data.decode('utf-8', errors='replace')
        # split mit maxsplit haelt den Speicher beschraenkt — der Rest
        # landet ungesplittet im letzten Element und wird verworfen
        lines = text.split('\n', self.MAX_LINES)
        if len(lines) > self.MAX_LINES:
            lines = lines[:self.MAX_LINES]
        return [l.rstrip('\r') for l in lines]
