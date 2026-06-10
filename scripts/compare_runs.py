#!/usr/bin/env python3
"""
Vergleicht zwei Pipeline-Laeufe (Vorher/Nachher) fuer die Fix-Validierung.

Verwendung:
    python scripts/compare_runs.py <lauf_A> <lauf_B>

<lauf_X> kann sein:
  - ein output-Verzeichnis  (enthaelt events.db und/oder case_*-Baum)
  - ein case_*-Verzeichnis direkt

Verglichen werden:
  - Events gesamt + Events pro Quelle (Parser)
  - text_fallback-Quote  (Gesundheitsindikator: unerkannte Dateien)
  - Events mit ungueltigem Timestamp (Jahr < 1990 oder > heute+1)
  - Anzahl extrahierter Dateien (raw/log_artefakte, raw/disk_artefakte)
  - Anti-Forensik / Findings aus JSON-Exports (falls vorhanden)
  - fruehestes / letztes Event
"""
import json
import sys
from datetime import datetime
from pathlib import Path


def find_events_db(root: Path):
    if (root / 'events.db').exists():
        return root / 'events.db'
    hits = sorted(root.rglob('events.db'), key=lambda p: p.stat().st_mtime)
    return hits[-1] if hits else None


def find_case_dir(root: Path):
    if root.name.startswith('case_'):
        return root
    cases = sorted(root.rglob('case_*'), key=lambda p: p.name)
    cases = [c for c in cases if c.is_dir()]
    return cases[-1] if cases else None


def count_files(d: Path):
    if not d or not d.is_dir():
        return 0
    return sum(1 for f in d.rglob('*') if f.is_file())


def analyse_run(root: Path) -> dict:
    r = {
        'pfad': str(root), 'events_total': 0, 'per_source': {},
        'fallback_events': 0, 'invalid_ts': 0,
        'earliest': '', 'latest': '',
        'log_artefakte': 0, 'disk_artefakte': 0,
        'findings': None, 'antiforensics': None, 'iocs': None,
    }
    db = find_events_db(root)
    if db:
        import duckdb
        con = duckdb.connect(str(db), read_only=True)
        r['events_total'] = con.execute('SELECT count(*) FROM events').fetchone()[0]
        r['per_source'] = dict(con.execute(
            'SELECT source, count(*) FROM events GROUP BY source ORDER BY 2 DESC'
        ).fetchall())
        r['fallback_events'] = sum(v for k, v in r['per_source'].items()
                                   if 'fallback' in (k or ''))
        r['invalid_ts'] = con.execute(
            "SELECT count(*) FROM events WHERE year(timestamp) < 1990 "
            "OR year(timestamp) > year(current_date) + 1").fetchone()[0]
        row = con.execute(
            "SELECT min(timestamp), max(timestamp) FROM events "
            "WHERE year(timestamp) >= 1990").fetchone()
        r['earliest'], r['latest'] = str(row[0] or ''), str(row[1] or '')
        con.close()

    case = find_case_dir(root)
    if case:
        r['log_artefakte']  = count_files(case / 'raw' / 'log_artefakte')
        r['disk_artefakte'] = count_files(case / 'raw' / 'disk_artefakte')
        # JSON-Exporte durchsuchen (Stage 8.5 / Stage 14)
        for jf in case.rglob('*.json'):
            try:
                data = json.loads(jf.read_text(errors='replace'))
            except Exception:
                continue
            if isinstance(data, dict):
                if 'antiforensics_hits' in data and r['antiforensics'] is None:
                    r['antiforensics'] = len(data['antiforensics_hits'])
                if 'iocs' in data and r['iocs'] is None:
                    r['iocs'] = len(data['iocs'])
            if isinstance(data, list) and 'finding' in jf.name.lower():
                r['findings'] = len(data)
    return r


def fmt(v):
    return 'n/a' if v is None else f'{v:,}' if isinstance(v, int) else str(v)


def delta(a, b):
    if isinstance(a, int) and isinstance(b, int):
        d = b - a
        return f'{"+" if d >= 0 else ""}{d:,}'
    return ''


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    A = analyse_run(Path(sys.argv[1]))
    B = analyse_run(Path(sys.argv[2]))

    print()
    print(f'  Lauf A: {A["pfad"]}')
    print(f'  Lauf B: {B["pfad"]}')
    print()
    rows = [
        ('Events gesamt',          A['events_total'],  B['events_total']),
        ('text_fallback-Events',   A['fallback_events'], B['fallback_events']),
        ('ungueltige Timestamps',  A['invalid_ts'],    B['invalid_ts']),
        ('Dateien log_artefakte',  A['log_artefakte'], B['log_artefakte']),
        ('Dateien disk_artefakte', A['disk_artefakte'],B['disk_artefakte']),
        ('Anti-Forensik-Treffer',  A['antiforensics'], B['antiforensics']),
        ('IOCs',                   A['iocs'],          B['iocs']),
        ('Findings (8.5)',         A['findings'],      B['findings']),
    ]
    print(f'  {"Metrik":<26} {"A":>12} {"B":>12} {"Delta":>10}')
    print('  ' + '-' * 64)
    for name, a, b in rows:
        print(f'  {name:<26} {fmt(a):>12} {fmt(b):>12} {delta(a, b):>10}')

    if A['events_total'] and A['fallback_events'] is not None:
        qa = 100 * A['fallback_events'] / max(A['events_total'], 1)
        qb = 100 * B['fallback_events'] / max(B['events_total'], 1)
        print(f'  {"fallback-Quote":<26} {qa:>11.1f}% {qb:>11.1f}%')

    print()
    print(f'  {"Zeitraum A":<14} {A["earliest"]}  ->  {A["latest"]}')
    print(f'  {"Zeitraum B":<14} {B["earliest"]}  ->  {B["latest"]}')

    # Quellen-Diff: was ist neu, was ist weg, was hat sich stark geaendert
    src_a, src_b = A['per_source'], B['per_source']
    neu      = sorted(set(src_b) - set(src_a))
    weg      = sorted(set(src_a) - set(src_b))
    gemeinsam= sorted(set(src_a) & set(src_b))

    print()
    print('  Events pro Quelle (Parser):')
    print(f'  {"Quelle":<28} {"A":>12} {"B":>12} {"Delta":>10}')
    print('  ' + '-' * 64)
    for s in sorted(set(src_a) | set(src_b),
                    key=lambda x: -(src_b.get(x, 0) + src_a.get(x, 0))):
        a, b = src_a.get(s, 0), src_b.get(s, 0)
        mark = '  NEU' if s in neu else ('  WEG' if s in weg else '')
        print(f'  {(s or "?"):<28} {a:>12,} {b:>12,} {delta(a, b):>10}{mark}')
    print()


if __name__ == '__main__':
    main()
