import json
import subprocess
import logging
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

log = logging.getLogger(__name__)

LEVEL_MAP = {'critical': 'critical', 'high': 'high', 'medium': 'medium',
             'low': 'info', 'informational': 'info'}


class EVTXParser(BaseParser):
    name          = 'evtx'
    file_patterns = ['*.evtx']
    binary        = True

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == '.evtx'

    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        hayabusa = self._find_hayabusa()
        if not hayabusa:
            log.warning('Hayabusa nicht gefunden — EVTX übersprungen')
            return []
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False) as tmp:
            out_file = tmp.name
        try:
            subprocess.run(
                [hayabusa, 'json-timeline', '--file', str(path),
                 '--output', out_file, '--no-wizard', '--quiet'],
                capture_output=True, timeout=600
            )
            if not Path(out_file).exists():
                return []
            with open(out_file, 'r', errors='replace') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        ts    = entry.get('Timestamp', '')
                        msg   = entry.get('Details', entry.get('RuleTitle', ''))
                        lvl   = entry.get('Level', 'informational').lower()
                        events.append(self.make_event(
                            ts, 'evtx', 'windows_event', str(msg),
                            severity=LEVEL_MAP.get(lvl, 'info'),
                            raw=entry
                        ))
                    except (json.JSONDecodeError, AttributeError):
                        continue
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass
        return events

    def _find_hayabusa(self):
        for candidate in ['/opt/hayabusa/hayabusa', './hayabusa', 'hayabusa']:
            p = Path(candidate)
            if p.exists():
                return str(p)
        try:
            result = subprocess.run(['which', 'hayabusa'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except FileNotFoundError:
            pass
        return None
