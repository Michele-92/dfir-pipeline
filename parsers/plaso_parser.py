import logging
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

log = logging.getLogger(__name__)


class PlasaFallbackParser(BaseParser):
    name          = 'plaso_fallback'
    file_patterns = ['*']

    def can_parse(self, path: Path) -> bool:
        return True  # Fallback — nimmt alles

    def parse(self, path: Path) -> List[ForensicEvent]:
        return self._text_fallback(path)

    def _text_fallback(self, path: Path) -> List[ForensicEvent]:
        events = []
        from datetime import datetime, timezone
        ts = datetime.now(tz=timezone.utc)
        try:
            for line in self.read_lines(path):
                if line.strip():
                    events.append(self.make_event(
                        ts, 'text_fallback', 'generic', line.strip(), severity='info'
                    ))
                    if len(events) >= 10000:
                        break
        except Exception:
            pass
        return events
