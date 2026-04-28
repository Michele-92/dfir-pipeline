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
    candidates = sorted(
        [p for p in base_dir.rglob('events.db') if 'case_' in str(p)],
        key=lambda p: p.stat().st_mtime
    )
    if candidates:
        return candidates[-1]
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

    # Events aus DB lesen
    print('Lese Events aus DuckDB...')
    limit = 50000
    with EventStore(db_path) as store:
        total = store.count()
        print(f'{total:,} Events in DB')
        if total > limit:
            print(f'Lade erste {limit:,} Events...')

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

    print(f'{min(total, limit):,} Events als JSONL gespeichert')

    # Zu Timesketch hochladen
    print(f'\nVerbinde mit Timesketch: {host}...')
    timeline_name = f'DFIR_{case_dir.name}'

    try:
        from timesketch_api_client import client as ts_client
        cli = ts_client.TimesketchApi(host, user, passwd)
        sk  = cli.get_sketch(sketch)

        # Zeige verfügbare Upload-Methoden
        upload_methods = [m for m in dir(sk) if any(
            kw in m.lower() for kw in ['timeline', 'upload', 'add', 'import']
        )]
        print(f'Verfügbare Methoden: {upload_methods}')

        uploaded = False

        # Methode 1: Authentifizierte Session + CSRF-Token explizit holen
        try:
            print('Verwende authentifizierte API-Session...')
            session = cli.session

            # CSRF-Token über GET-Request holen
            session.get(f'{host}/')
            csrf = session.cookies.get('csrftoken', '')
            print(f'CSRF Token nach GET: {bool(csrf)}')

            if not csrf:
                # Zweiter Versuch über Login-Seite
                session.get(f'{host}/login/')
                csrf = session.cookies.get('csrftoken', '')
                print(f'CSRF Token nach /login/ GET: {bool(csrf)}')

            if csrf:
                with open(tmp_jsonl, 'rb') as f:
                    resp = session.post(
                        f'{host}/api/v1/upload/',
                        headers={
                            'X-CSRFToken': csrf,
                            'Referer': f'{host}/',
                        },
                        files={'file': (f'{timeline_name}.jsonl', f, 'application/jsonlines')},
                        data={'name': timeline_name, 'sketch_id': str(sketch)},
                    )
                print(f'Upload → Status {resp.status_code}')
                if resp.status_code in (200, 201):
                    uploaded = True
                    print('Upload via API-Session erfolgreich')
                else:
                    print(f'Antwort: {resp.text[:300]}')
            else:
                print('Kein CSRF Token erhältlich')
        except Exception as e:
            print(f'API-Session Upload fehlgeschlagen: {e}')

        # Methode 2: timesketch_import_client Python API
        if not uploaded:
            try:
                from timesketch_import_client import importer
                print('Verwende ImportStreamer...')
                with importer.ImportStreamer() as streamer:
                    streamer.set_sketch(sk)
                    streamer.set_timeline_name(timeline_name)
                    streamer.add_file(str(tmp_jsonl))
                uploaded = True
                print('Upload via ImportStreamer erfolgreich')
            except ImportError:
                print('timesketch_import_client nicht installiert')
            except Exception as e:
                print(f'ImportStreamer fehlgeschlagen: {e}')

        # Methode 2: REST API mit korrektem Login
        if not uploaded:
            print('Verwende REST API...')
            import requests
            session = requests.Session()

            # Login-Seite aufrufen für CSRF-Token
            r = session.get(f'{host}/login/')
            csrf = session.cookies.get('csrftoken', '')
            print(f'CSRF Token: {csrf[:20]}...' if csrf else 'Kein CSRF Token')

            # Einloggen
            r = session.post(
                f'{host}/login/',
                data={
                    'username': user,
                    'password': passwd,
                    'csrfmiddlewaretoken': csrf,
                },
                headers={
                    'Referer': f'{host}/login/',
                    'X-CSRFToken': csrf,
                }
            )
            print(f'Login Status: {r.status_code}')

            # Neuen CSRF-Token nach Login holen
            csrf = session.cookies.get('csrftoken', csrf)

            # Timeline erstellen via REST
            with open(tmp_jsonl, 'rb') as f:
                resp = session.post(
                    f'{host}/api/v1/sketches/{sketch}/timelines/',
                    headers={
                        'X-CSRFToken': csrf,
                        'Referer': f'{host}/',
                    },
                    files={'file': (f'{timeline_name}.jsonl', f, 'application/jsonlines')},
                    data={'name': timeline_name},
                )
            print(f'Upload Status: {resp.status_code}')
            if resp.status_code in (200, 201):
                uploaded = True
                print('Upload via REST API erfolgreich')
            else:
                print(f'REST Fehler: {resp.text[:300]}')

        if not uploaded:
            print('\nHINWEIS: Installiere timesketch-import-client:')
            print('pip install timesketch-import-client')
            sys.exit(1)

        url = f'{host}/sketch/{sketch}/explore'
        print(f'\nErfolgreich! Timesketch URL: {url}')
        (case_dir / 'timesketch_link.txt').write_text(
            f'Timesketch URL: {url}\nErstellt: {datetime.utcnow().isoformat()}Z\n'
        )

    except Exception as e:
        print(f'FEHLER: {e}')
        sys.exit(1)
    finally:
        if tmp_jsonl.exists():
            tmp_jsonl.unlink()


if __name__ == '__main__':
    main()
