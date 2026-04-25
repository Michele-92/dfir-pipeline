import json
import logging
from pathlib import Path
from typing import Dict, List

from tqdm import tqdm
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

KEYWORD_MAP = {
    # T1053 — Scheduled Task / Cron
    'crontab':        ('T1053.003', 0.8),
    'cron.d':         ('T1053.003', 0.7),
    'systemd timer':  ('T1053.006', 0.7),

    # T1070 — Indicator Removal
    '> /var/log':     ('T1070.002', 0.9),
    'truncate -s 0':  ('T1070.002', 0.95),
    'rm -f /var/log': ('T1070.002', 0.95),
    'shred':          ('T1070.002', 0.8),
    'history -c':     ('T1070.003', 0.9),
    'unset histfile': ('T1070.003', 0.95),

    # T1078 — Valid Accounts
    'accepted password':   ('T1078', 0.6),
    'accepted publickey':  ('T1078', 0.6),

    # T1059 — Command and Scripting
    'bash -i':        ('T1059.004', 0.9),
    'python -c':      ('T1059.006', 0.85),
    'perl -e':        ('T1059.006', 0.85),
    '/bin/sh':        ('T1059.004', 0.7),

    # T1105 — Ingress Tool Transfer
    'wget ':          ('T1105', 0.7),
    'curl ':          ('T1105', 0.7),
    'scp ':           ('T1105', 0.6),
    'sftp ':          ('T1105', 0.6),

    # T1003 — Credential Dumping
    '/etc/shadow':    ('T1003.008', 0.9),
    '/etc/passwd':    ('T1003.008', 0.7),
    'hashdump':       ('T1003', 0.95),
    'mimikatz':       ('T1003.001', 0.99),

    # T1098 — Account Manipulation
    'useradd':        ('T1098', 0.8),
    'usermod':        ('T1098', 0.8),
    'new user:':      ('T1098', 0.85),

    # T1543 — Create/Modify System Process
    'systemctl enable':    ('T1543.002', 0.8),
    'systemctl daemon-reload': ('T1543.002', 0.7),
    '.service':            ('T1543.002', 0.5),

    # T1562 — Disable Security Tools
    'ufw disable':      ('T1562.004', 0.95),
    'iptables -f':      ('T1562.004', 0.9),
    'systemctl stop ufw': ('T1562.004', 0.9),
    'setenforce 0':     ('T1562.001', 0.95),

    # T1110 — Brute Force
    'failed password':     ('T1110.001', 0.8),
    'authentication failure': ('T1110', 0.75),
    'invalid user':        ('T1110.001', 0.8),

    # T1021 — Remote Services
    'ssh ':            ('T1021.004', 0.5),
    'rdp':             ('T1021.001', 0.7),

    # T1040 — Network Sniffing
    'tcpdump':         ('T1040', 0.7),
    'wireshark':       ('T1040', 0.6),
    'tshark':          ('T1040', 0.6),

    # T1027 — Obfuscated Files
    'base64':          ('T1027', 0.7),
    'xxd -r':          ('T1027', 0.8),

    # T1505 — Server Software Component
    'webshell':        ('T1505.003', 0.95),
    'php eval':        ('T1505.003', 0.9),

    # T1082 — System Information Discovery
    'uname -a':        ('T1082', 0.6),
    'cat /etc/os-release': ('T1082', 0.6),

    # T1083 — File and Directory Discovery
    'find / ':         ('T1083', 0.6),
    'ls -la':          ('T1083', 0.4),

    # T1046 — Network Service Scanning
    'nmap':            ('T1046', 0.9),
    'masscan':         ('T1046', 0.9),
    'netstat':         ('T1046', 0.4),

    # T1014 — Rootkit
    'insmod':          ('T1014', 0.85),
    'ld_preload':      ('T1014', 0.9),
    'sys_call_table':  ('T1014', 0.95),
}


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 9: MITRE ATT&CK Mapping')
    techniques = _load_attack_db()
    hits       = _map_events(ctx.normalized_events, techniques)
    hits      += _map_antiforensics(ctx.antiforensics_hits, techniques)
    hits       = _deduplicate(hits)

    ctx.mitre_hits = hits
    log.info(f'  {len(hits)} MITRE ATT&CK Techniken gefunden')
    if ctx.coc:
        ctx.coc.add_entry('stage_09', f'MITRE: {len(hits)} Techniken')
    return ctx


def _load_attack_db() -> Dict:
    db_path = Path(__file__).parent.parent / 'data' / 'enterprise-attack-v15.json'
    techniques = {}
    if not db_path.exists():
        log.warning('enterprise-attack-v15.json nicht gefunden — leere Technik-DB')
        return techniques
    try:
        with open(db_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                ext = obj.get('external_references', [])
                for ref in ext:
                    if ref.get('source_name') == 'mitre-attack':
                        tid = ref.get('external_id', '')
                        techniques[tid] = {
                            'name':    obj.get('name', ''),
                            'tactics': [p['phase_name'] for p in
                                        obj.get('kill_chain_phases', [])],
                            'description': obj.get('description', '')[:200],
                        }
    except Exception as e:
        log.warning(f'ATT&CK DB Ladefehler: {e}')
    return techniques


def _map_events(events, techniques: Dict) -> List[Dict]:
    hits = []
    for event in tqdm(events, desc='  MITRE ATT&CK Mapping', unit='Event', dynamic_ncols=True):
        msg_lower = event.message.lower()
        for keyword, (tech_id, confidence) in KEYWORD_MAP.items():
            if keyword.lower() in msg_lower:
                tech = techniques.get(tech_id, {})
                hits.append({
                    'technique_id':    tech_id,
                    'technique_name':  tech.get('name', 'Unbekannt'),
                    'tactics':         tech.get('tactics', []),
                    'confidence':      confidence,
                    'event_timestamp': event.timestamp.isoformat(),
                    'event_message':   event.message[:300],
                    'event_source':    event.source,
                    'keyword_matched': keyword,
                })
                event.mitre_tags.append(tech_id)
                break
    return hits


def _map_antiforensics(af_hits: List[Dict], techniques: Dict) -> List[Dict]:
    hits = []
    for hit in af_hits:
        text = hit.get('details', '').lower()
        for keyword, (tech_id, confidence) in KEYWORD_MAP.items():
            if keyword.lower() in text:
                tech = techniques.get(tech_id, {})
                hits.append({
                    'technique_id':    tech_id,
                    'technique_name':  tech.get('name', 'Unbekannt'),
                    'tactics':         tech.get('tactics', []),
                    'confidence':      confidence,
                    'event_timestamp': hit.get('timestamp', ''),
                    'event_message':   hit.get('details', '')[:300],
                    'event_source':    hit.get('source', 'antiforensics'),
                    'keyword_matched': keyword,
                })
                break
    return hits


def _deduplicate(hits: List[Dict]) -> List[Dict]:
    seen    = {}
    result  = []
    for hit in hits:
        key = hit['technique_id']
        if key not in seen:
            seen[key] = hit
            result.append(hit)
        elif hit['confidence'] > seen[key]['confidence']:
            seen[key] = hit
            idx = next(i for i, h in enumerate(result) if h['technique_id'] == key)
            result[idx] = hit
    return result
