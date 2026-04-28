#!/usr/bin/env python3
"""
Timesketch Upload Script
Sucht automatisch die neueste events.db und speichert JSONL im Case-Ordner.
Verwendung: python upload_timesketch.py
"""
import json
import re
import sys
from pathlib import Path
from datetime import datetime

import yaml

from utils.event_store import EventStore


def find_events_db(output_dir: Path) -> Path:
    """Findet die events.db im Output-Verzeichnis."""
    db = output_dir / 'events.db'
    if db.exists():
        return db
    candidates = sorted(output_dir.rglob('events.db'), key=lambda p: p.stat().st_mtime)
    if not candidates:
        raise FileNotFoundError(f'Keine events.db in {output_dir} gefunden')
    return candidates[-1]


def find_latest_case_dir(output_dir: Path) -> Path:
    """Findet das neueste Case-Verzeichnis anhand von pipeline_report.json."""
    candidates = sorted(
        output_dir.rglob('pipeline_report.json'),
        key=lambda p: p.stat().st_mtime
    )
    if candidates:
        return candidates[-1].parent
    # Fallback: neuestes case_* Verzeichnis
    candidates = sorted(
        [p for p in output_dir.rglob('*') if p.is_dir() and 'case_' in p.name],
        key=lambda p: p.stat().st_mtime
    )
    if candidates:
        return candidates[-1]
    return output_dir


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

    output_dir = Path.home() / 'output'
    if not output_dir.exists():
        output_dir = script_dir / 'output'

    # events.db und Case-Verzeichnis finden
    print(f'Suche in {output_dir}...')
    db_path  = find_events_db(output_dir)
    case_dir = find_latest_case_dir(output_dir)
    print(f'events.db:      {db_path}')
    print(f'Case-Ordner:    {case_dir}')

    # JSONL im Case-Ordner speichern
    jsonl_path = case_dir / 'events_upload.jsonl'
    timeline_name = f'DFIR_{case_dir.name}'

    print('Lese Events aus DuckDB...')
    limit = 50000
    with EventStore(db_path) as store:
        total = store.count()
        print(f'{total:,} Events in DB')
        if total > limit:
            print(f'Lade erste {limit:,} Events...')
        skipped = 0
        with open(jsonl_path, 'w') as f:
            written = 0
            for e in store.iter_events():
                if written >= limit:
                    break
                if e.timestamp.year < 1970:
                    skipped += 1
                    continue
                f.write(json.dumps({
                    'datetime':       e.timestamp.isoformat(),
                    'timestamp_desc': e.event_type or 'generic',
                    'message':        e.message,
                    'source':         e.source,
                }) + '\n')
                written += 1
        if skipped:
            print(f'{skipped:,} Events mit ungültigem Timestamp übersprungen')

    print(f'{min(total, limit):,} Events gespeichert → {jsonl_path}')

    # Verbindung zu Timesketch
    print(f'\nVerbinde mit Timesketch: {host}...')
    try:
        from timesketch_api_client import client as ts_client
        cli = ts_client.TimesketchApi(host, user, passwd)
        sk  = cli.get_sketch(sketch)
        session = cli.session

        # CSRF-Token aus HTML holen
        csrf = ''
        for url in [f'{host}/sketch/{sketch}/', f'{host}/']:
            r = session.get(url)
            for pattern in [
                r'csrf_token.*?value="([^"]+)"',
                r'<meta name="csrf-token" content="([^"]+)"',
                r'"csrfToken":\s*"([^"]+)"',
            ]:
                m = re.search(pattern, r.text, re.IGNORECASE)
                if m:
                    csrf = m.group(1)
                    break
            if csrf:
                break

        uploaded = False

        if csrf:
            with open(jsonl_path, 'rb') as f:
                resp = session.post(
                    f'{host}/api/v1/upload/',
                    headers={'X-CSRFToken': csrf, 'Referer': f'{host}/'},
                    files={'file': (f'{timeline_name}.jsonl', f, 'application/jsonlines')},
                    data={'name': timeline_name, 'sketch_id': str(sketch)},
                )
            if resp.status_code in (200, 201):
                uploaded = True
                print('Upload erfolgreich!')

        if not uploaded:
            print('\n── Upload über Docker-Container ──────────────────────')
            print('Führe diese 3 Befehle nacheinander aus:\n')
            print(f'  sudo docker cp {jsonl_path} timesketch-web:/tmp/events_upload.jsonl')
            print(f'  sudo docker cp {script_dir}/upload_inside_container.py timesketch-web:/tmp/upload_inside_container.py')
            print(f'  sudo docker exec timesketch-web python3 /tmp/upload_inside_container.py')
            print()
            sys.exit(1)

        url = f'{host}/sketch/{sketch}/explore'
        print(f'Timesketch URL: {url}')
        (case_dir / 'timesketch_link.txt').write_text(
            f'Timesketch URL: {url}\nErstellt: {datetime.utcnow().isoformat()}Z\n'
        )

    except Exception as e:
        print(f'FEHLER: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
