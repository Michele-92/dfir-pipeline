import json
import subprocess
import logging
import tempfile
import os
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
        events = []
        try:
            result = subprocess.run(
                ['log2timeline.py', '--status_view', 'none',
                 '--logfile', '/dev/null', '/tmp/plaso_out.plaso', str(path)],
                capture_output=True, timeout=300
            )
            if result.returncode != 0:
                raise RuntimeError('log2timeline fehlgeschlagen')
            psort = subprocess.run(
                ['psort.py', '-o', 'json_line', '/tmp/plaso_out.plaso'],
                capture_output=True, text=True, timeout=300
            )
            for line in psort.stdout.splitlines():
                try:
                    entry = json.loads(line)
                    ts    = entry.get('datetime', '')
                    msg   = entry.get('message', '')
                    src   = entry.get('source_long', 'plaso')
                    events.append(self.make_event(
                        ts, 'plaso', 'generic_event', msg,
                        severity='info', raw=entry
                    ))
                except (json.JSONDecodeError, AttributeError):
                    continue
        except (FileNotFoundError, subprocess.TimeoutExpired, RuntimeError) as e:
            log.debug(f'Plaso nicht verfügbar oder Fehler: {e}')
            events = self._text_fallback(path)
        return events

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
