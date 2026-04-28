#!/usr/bin/env python3
"""
Timesketch Upload Script
Sucht automatisch die neueste events.db und lädt alle Events hoch.
Verwendung: python upload_timesketch.py
"""
import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime

import yaml

from utils.event_store import EventStore


def find_latest_case_dir(base_dir: Path) -> Path:
    """Findet das neueste Case-Verzeichnis mit events.db."""
    # Suche zuerst in Case-Unterverzeichnissen
    candidates = sorted(
        [p for p in base_dir.rglob('events.db') if 'case_' in str(p)],
        key=lambda p: p.stat().st_mtime
    )
    if candidates:
        return candidates[-1]
    # Fallback: alle events.db
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
    db_path = find_latest_case_dir(output_dir)
    case_dir = db_path.parent
    print(f'Gefunden: {db_path}')
    print(f'Case-Verzeichnis: {case_dir.name}')

    # Events aus DB lesen und als JSONL-Datei speichern
    print('Lese Events aus DuckDB...')
    limit = 50000
    with EventStore(db_path) as store:
        total = store.count()
        print(f'{total:,} Events in DB')
        if total > limit:
            print(f'Lade erste {limit:,} Events (Timesketch-Limit)...')

        tmp_jsonl = Path(tempfile.mktemp(suffix='.jsonl'))
        with open(tmp_jsonl, 'w') as f:
            for i, e in enumerate(store.iter_events()):
                if i >= limit:
                    break
                row = {
                    'datetime':       e.timestamp.isoformat(),
                    'timestamp_desc': e.event_type or 'generic',
                    'message':        e.message,
                    'source':         e.source,
                }
                f.write(json.dumps(row) + '\n')

    print(f'Events als JSONL gespeichert: {tmp_jsonl}')

    # Zu Timesketch hochladen
    print(f'Verbinde mit Timesketch: {host}...')
    try:
        from timesketch_api_client import client as ts_client
        cli = ts_client.TimesketchApi(host, user, passwd)
        sk  = cli.get_sketch(sketch)

        timeline_name = f'DFIR_{case_dir.name}'
        print(f'Lade hoch als Timeline: {timeline_name}...')

        # Versuche verschiedene Upload-Methoden je nach API-Version
        uploaded = False

        # Methode 1: timesketch_import_client (neueste Version)
        try:
            from timesketch_import_client import importer
            with importer.ImportStreamer() as streamer:
                streamer.set_sketch(sk)
                streamer.set_timeline_name(timeline_name)
                streamer.add_file(str(tmp_jsonl))
            uploaded = True
            print('Upload via ImportStreamer erfolgreich')
        except ImportError:
            pass
        except Exception as e:
            print(f'ImportStreamer fehlgeschlagen: {e}')

        # Methode 2: add_timeline_from_json (ältere Version)
        if not uploaded:
            try:
                events = [json.loads(line) for line in open(tmp_jsonl)]
                sk.add_timeline_from_json(json.dumps(events), timeline_name=timeline_name)
                uploaded = True
                print('Upload via add_timeline_from_json erfolgreich')
            except Exception as e:
                print(f'add_timeline_from_json fehlgeschlagen: {e}')

        # Methode 3: Direkt via REST API
        if not uploaded:
            import requests
            session = requests.Session()
            r = session.get(f'{host}/api/v1/sketches/{sketch}/',
                           auth=(user, passwd))
            csrf = r.cookies.get('csrftoken', '')
            with open(tmp_jsonl, 'rb') as f:
                resp = session.post(
                    f'{host}/api/v1/sketches/{sketch}/timelines/',
                    headers={'X-CSRFToken': csrf, 'Referer': host},
                    files={'file': (f'{timeline_name}.jsonl', f, 'application/json')},
                    data={'name': timeline_name},
                    auth=(user, passwd)
                )
            if resp.status_code in (200, 201):
                uploaded = True
                print('Upload via REST API erfolgreich')
            else:
                print(f'REST API Fehler: {resp.status_code} {resp.text[:200]}')

        if not uploaded:
            print('FEHLER: Kein Upload-Verfahren hat funktioniert')
            sys.exit(1)

        url = f'{host}/sketch/{sketch}/explore'
        print(f'\nErfolgreich hochgeladen!')
        print(f'Timesketch URL: {url}')

        (case_dir / 'timesketch_link.txt').write_text(
            f'Timesketch URL: {url}\n'
            f'Erstellt: {datetime.utcnow().isoformat()}Z\n'
        )

    except Exception as e:
        print(f'FEHLER: {e}')
        sys.exit(1)
    finally:
        if tmp_jsonl.exists():
            tmp_jsonl.unlink()


if __name__ == '__main__':
    main()
