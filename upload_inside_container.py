#!/usr/bin/env python3
"""
Läuft INNERHALB des timesketch-web Containers.
Lädt events_upload.jsonl direkt auf localhost:5000 hoch.
"""
import json
import sys
import re
import requests

HOST      = 'http://localhost:5000'
USER      = 'admin'
PASSWORD  = 'changeme'   # anpassen falls nötig
SKETCH_ID = 1
JSONL     = '/tmp/events_upload.jsonl'
NAME      = 'DFIR_Pipeline_Export'

session = requests.Session()

# Login-Seite → CSRF holen
r = session.get(f'{HOST}/login/')
csrf = session.cookies.get('csrf_token', '')
if not csrf:
    m = re.search(r'csrf.token.*?value="([^"]+)"', r.text, re.IGNORECASE)
    if m:
        csrf = m.group(1)

print(f'CSRF: {bool(csrf)}')

# Einloggen
r = session.post(
    f'{HOST}/login/',
    data={'username': USER, 'password': PASSWORD, 'csrf_token': csrf},
    headers={'X-CSRFToken': csrf, 'Referer': f'{HOST}/login/'},
)
print(f'Login: {r.status_code}')

# Neuen CSRF nach Login
csrf = session.cookies.get('csrf_token', csrf)
r2 = session.get(f'{HOST}/sketch/{SKETCH_ID}/')
m = re.search(r'csrf.token.*?value="([^"]+)"', r2.text, re.IGNORECASE)
if m:
    csrf = m.group(1)
print(f'CSRF nach Login: {bool(csrf)}')

# Upload
with open(JSONL, 'rb') as f:
    resp = session.post(
        f'{HOST}/api/v1/upload/',
        headers={'X-CSRFToken': csrf, 'Referer': f'{HOST}/'},
        files={'file': (f'{NAME}.jsonl', f, 'application/jsonlines')},
        data={'name': NAME, 'sketch_id': str(SKETCH_ID)},
    )

print(f'Upload Status: {resp.status_code}')
print(f'Antwort: {resp.text[:300]}')
