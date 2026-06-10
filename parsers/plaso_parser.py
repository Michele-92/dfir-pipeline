import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

log = logging.getLogger(__name__)


class PlasaFallbackParser(BaseParser):
    """Text-Fallback fuer Dateien ohne passenden Parser.

    Review-Fix HIGH #15: Hiess frueher 'plaso_fallback', ist aber KEIN Plaso —
    nur ein Zeilen-Dump. Timestamps waren der Analysezeitpunkt (Timeline-
    Verfaelschung!), jetzt: mtime der extrahierten Datei + Kennzeichnung
    'unparsed_text', damit die Events filterbar und ehrlich markiert sind.
    """
    name          = 'text_fallback'
    file_patterns = ['*']

    def can_parse(self, path: Path) -> bool:
        return True  # Fallback — nimmt alles

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            ts = datetime.now(tz=timezone.utc)
        try:
            for line in self.read_lines(path):
                if line.strip():
                    events.append(self.make_event(
                        ts, 'text_fallback', 'unparsed_text',
                        line.strip(), severity='info'
                    ))
                    if len(events) >= 10000:
                        break
        except Exception:
            pass
        return events
