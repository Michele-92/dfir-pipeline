#!/usr/bin/env python3
"""
Timesketch Upload Script
Sucht automatisch die neueste events.db und lädt alle Events hoch.
Verwendung: python upload_timesketch.py
"""
import json
import sys
from pathlib import Path
from datetime import datetime

import yaml

from utils.event_store import EventStore


def find_latest_events_db(base_dir: Path) -> Path:
    """Findet die neueste events.db im Output-Verzeichnis."""
    candidates = sorted(base_dir.rglob('events.db'), key=lambda p: p.stat().st_mtime)
    if not candidates:
        raise FileNotFoundError(f'Keine events.db in {base_dir} gefunden')
    return candidates[-1]


def main():
    script_dir = Path(__file__).parent
    config_path = script_dir / 'config.yaml'

    if not config_path.exists():
        print('FEHLER: config.yaml nicht gefunden')
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    ts_cfg  = cfg.get('timesketch', {})
    host    = ts_cfg.get('host', 'http://localhost')
    user    = ts_cfg.get('username', 'admin')
    passwd  = ts_cfg.get('password', 'changeme')
    sketch  = ts_cfg.get('sketch_id', 1)

    # Neueste events.db suchen
    output_dir = Path.home() / 'output'
    if not output_dir.exists():
        output_dir = script_dir / 'output'

    print(f'Suche events.db in {output_dir}...')
    db_path = find_latest_events_db(output_dir)
    case_dir = db_path.parent
    print(f'Gefunden: {db_path}')
    print(f'Case-Verzeichnis: {case_dir}')

    # Events aus DB lesen
    print('Lese Events aus DuckDB...')
    with EventStore(db_path) as store:
        total = store.count()
        print(f'{total:,} Events in DB')

        limit = 50000
        if total > limit:
            print(f'Lade erste {limit:,} Events (Timesketch-Limit)...')

        events = []
        for i, e in enumerate(store.iter_events()):
            if i >= limit:
                break
            events.append({
                'datetime':       e.timestamp.isoformat(),
                'timestamp_desc': e.event_type,
                'message':        e.message,
                'source':         e.source,
            })

    print(f'{len(events):,} Events vorbereitet')

    # Zu Timesketch hochladen
    print(f'Verbinde mit Timesketch: {host}...')
    try:
        from timesketch_api_client import client as ts_client
        cli = ts_client.TimesketchApi(host, user, passwd)
        sk  = cli.get_sketch(sketch)

        timeline_name = f'DFIR_{case_dir.name}'
        print(f'Lade hoch als Timeline: {timeline_name}...')
        sk.add_timeline_from_json(json.dumps(events), timeline_name=timeline_name)

        url = f'{host}/sketch/{sketch}/explore'
        print(f'\nErfolgreich hochgeladen!')
        print(f'Timesketch URL: {url}')

        # Link-Datei aktualisieren
        (case_dir / 'timesketch_link.txt').write_text(
            f'Timesketch URL: {url}\n'
            f'Erstellt: {datetime.utcnow().isoformat()}Z\n'
        )

    except Exception as e:
        print(f'FEHLER beim Upload: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
