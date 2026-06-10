"""Parser fuer wtmpdb — der Y2038-sichere wtmp-Nachfolger (SQLite).

Moderne Distributionen (z.B. openSUSE, Fedora ab 2023+) ersetzen
/var/log/wtmp durch eine SQLite-Datenbank /var/lib/wtmpdb/wtmp.db.
Tabelle 'wtmp': ID, Type, User, Login, Logout, TTY, RemoteHost, Service
— Login/Logout als Mikrosekunden seit Epoch (int64).
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.event import ForensicEvent
from parsers.base_parser import BaseParser

# wtmpdb.h: EMPTY=0, BOOT_TIME=1, RUNLEVEL=2, USER_PROCESS=3
WTMPDB_TYPES = {0: 'empty', 1: 'boot_time', 2: 'run_level', 3: 'user_process'}


class WtmpdbParser(BaseParser):
    name          = 'wtmpdb'
    file_patterns = ['wtmp.db']
    binary        = True

    def can_parse(self, path: Path) -> bool:
        return (path.name == 'wtmp.db'
                or 'wtmpdb' in str(path).lower())

    def parse(self, path: Path) -> List[ForensicEvent]:
        events: List[ForensicEvent] = []
        try:
            con = sqlite3.connect(f'file:{path}?mode=ro&immutable=1', uri=True)
        except sqlite3.Error:
            return events
        try:
            cur  = con.cursor()
            cols = [r[1] for r in cur.execute('PRAGMA table_info(wtmp)')]
            if not cols:
                return events
            for row in cur.execute('SELECT * FROM wtmp'):
                d        = dict(zip(cols, row))
                user     = str(d.get('User') or '')
                tty      = str(d.get('TTY') or '')
                host     = str(d.get('RemoteHost') or '')
                wtype    = d.get('Type')
                tname    = WTMPDB_TYPES.get(wtype, f'type_{wtype}')

                login_us  = d.get('Login')
                logout_us = d.get('Logout')

                if login_us:
                    events.append(self.make_event(
                        self._ts(login_us), 'wtmpdb', f'{tname}_login',
                        f'wtmpdb Login: User={user} TTY={tty} Host={host}',
                        user=user or None, ip=host or None,
                        severity='medium' if tname == 'user_process' else 'info',
                    ))
                if logout_us:
                    events.append(self.make_event(
                        self._ts(logout_us), 'wtmpdb', f'{tname}_logout',
                        f'wtmpdb Logout: User={user} TTY={tty}',
                        user=user or None, severity='info',
                    ))
        except sqlite3.Error:
            pass
        finally:
            con.close()
        return events

    @staticmethod
    def _ts(usec) -> datetime:
        return datetime.fromtimestamp(int(usec) / 1_000_000, tz=timezone.utc)
