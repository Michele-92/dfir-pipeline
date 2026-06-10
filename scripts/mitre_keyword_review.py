"""
Script: mitre_keyword_review.py
Zweck:  Alle Linux-spezifischen MITRE ATT&CK Techniken aus enterprise-attack-v15.json
        extrahieren und als Markdown-Tabelle ausgeben zum manuellen Review.

Output: mitre_keyword_review.md — eine Tabelle mit offiziellen MITRE-Beschreibungen
        die der Nutzer manuell mit Keywords ergaenzt.
"""

import json
from pathlib import Path

# Offizielle Linux-Techniken von attack.mitre.org/matrices/enterprise/linux/
# Quelle: MITRE ATT&CK Enterprise Linux Matrix v15
# Nur Haupt-T-Nummern — Sub-Techniken werden aus der JSON geladen
OFFICIAL_LINUX_TECHNIQUES = {
    # Initial Access
    'T1659', 'T1189', 'T1190', 'T1133', 'T1200', 'T1566', 'T1195', 'T1199', 'T1078', 'T1669',
    # Execution
    'T1059', 'T1203', 'T1574', 'T1674', 'T1559', 'T1106', 'T1053', 'T1129', 'T1072', 'T1569', 'T1204',
    # Persistence
    'T1098', 'T1547', 'T1037', 'T1554', 'T1136', 'T1543', 'T1546', 'T1668',
    'T1556', 'T1653', 'T1542', 'T1505', 'T1176', 'T1205',
    # Privilege Escalation
    'T1548', 'T1611', 'T1068', 'T1055',
    # Defense Evasion (Stealth)
    'T1622', 'T1678', 'T1140', 'T1480', 'T1211', 'T1564', 'T1070',
    'T1036', 'T1620', 'T1218', 'T1497', 'T1553',
    # Defense Impairment
    'T1222', 'T1690',
    # Credential Access
    'T1557', 'T1110', 'T1555', 'T1212', 'T1606', 'T1056', 'T1111',
    'T1621', 'T1040', 'T1003', 'T1649', 'T1558', 'T1539', 'T1552',
    # Discovery
    'T1087', 'T1217', 'T1652', 'T1083', 'T1680', 'T1654', 'T1046',
    'T1135', 'T1201', 'T1120', 'T1069', 'T1057', 'T1018', 'T1518',
    'T1082', 'T1614', 'T1016', 'T1049', 'T1033', 'T1007', 'T1124', 'T1673',
    # Lateral Movement
    'T1210', 'T1534', 'T1570', 'T1563', 'T1021', 'T1080', 'T1550',
    # Collection
    'T1560', 'T1123', 'T1119', 'T1115', 'T1213', 'T1005',
    'T1039', 'T1074', 'T1114', 'T1113', 'T1125',
    # Command and Control
    'T1071', 'T1132', 'T1568', 'T1573', 'T1105', 'T1095',
    'T1571', 'T1572', 'T1090', 'T1219', 'T1102',
    # Exfiltration
    'T1048', 'T1041', 'T1567',
    # Impact
    'T1485', 'T1486', 'T1490', 'T1496', 'T1489', 'T1529', 'T1531',
}

# Techniken die zwar in der Linux-Matrix stehen aber NICHT via
# einfache Log-Keyword-Analyse erkennbar sind
EXCLUDE_NOT_DETECTABLE = {
    'T1659', 'T1189', 'T1190', 'T1200', 'T1566', 'T1195', 'T1199', 'T1669',  # Initial Access
    'T1203', 'T1674', 'T1559', 'T1106', 'T1129', 'T1072', 'T1204',           # Execution (generisch)
    'T1554', 'T1668', 'T1653', 'T1542', 'T1176', 'T1205',                     # Persistence (generisch)
    'T1611',                                                                    # Escape to Host
    'T1622', 'T1678', 'T1140', 'T1480', 'T1211', 'T1620', 'T1218', 'T1497',  # Evasion (generisch)
    'T1553',                                                                    # Subvert Trust
    'T1557', 'T1212', 'T1606', 'T1111', 'T1621', 'T1649', 'T1558', 'T1539',  # Cred Access (generisch)
    'T1217', 'T1652', 'T1680', 'T1120', 'T1018', 'T1614', 'T1016',           # Discovery (generisch)
    'T1673', 'T1124',
    'T1210', 'T1534', 'T1080', 'T1550',                                        # Lateral (generisch)
    'T1123', 'T1119', 'T1115', 'T1213', 'T1005', 'T1039', 'T1125',           # Collection (generisch)
    'T1071', 'T1132', 'T1568', 'T1573', 'T1095', 'T1102',                    # C2 (generisch)
    'T1048', 'T1041', 'T1567',                                                 # Exfil (generisch)
    'T1485', 'T1531',                                                           # Impact (generisch)
}

# Bereits implementierte T-Nummern in stage11_mitre.py
ALREADY_IMPLEMENTED = {
    'T1053.003', 'T1053.006', 'T1070.002', 'T1070.003', 'T1078',
    'T1059.004', 'T1059.006', 'T1105', 'T1003', 'T1003.001', 'T1003.008',
    'T1098', 'T1543.002', 'T1562.004', 'T1562.001', 'T1110', 'T1110.001',
    'T1021.004', 'T1021.001', 'T1040', 'T1027', 'T1505.003', 'T1082',
    'T1083', 'T1046', 'T1014'
}

def load_linux_techniques(json_path: Path) -> list:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    techniques = []
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        platforms = obj.get('x_mitre_platforms', [])
        if 'Linux' not in platforms:
            continue

        tid = ''
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tid = ref.get('external_id', '')

        if not tid or tid in ALREADY_IMPLEMENTED:
            continue

        # Nur offizielle Linux-Techniken von attack.mitre.org/matrices/enterprise/linux/
        # Prüfe ob T-Nummer oder die Haupt-T-Nummer (ohne Sub-Technik) in der Liste ist
        base_tid = tid.split('.')[0]
        if tid not in OFFICIAL_LINUX_TECHNIQUES and base_tid not in OFFICIAL_LINUX_TECHNIQUES:
            continue

        # Nicht via Log-Keywords erkennbar — ausschliessen
        if tid in EXCLUDE_NOT_DETECTABLE or base_tid in EXCLUDE_NOT_DETECTABLE:
            continue

        tactics = [p['phase_name'] for p in obj.get('kill_chain_phases', [])]
        description = obj.get('description', '').strip()
        # Ersten Absatz der Beschreibung nehmen (bis zum ersten Doppel-Newline)
        first_para = description.split('\n\n')[0].replace('\n', ' ').strip()
        # Auf 400 Zeichen begrenzen
        if len(first_para) > 400:
            first_para = first_para[:400] + '...'

        techniques.append({
            'id':          tid,
            'name':        obj.get('name', ''),
            'tactics':     ', '.join(tactics),
            'description': first_para,
        })

    techniques.sort(key=lambda x: x['id'])
    return techniques


def write_markdown(techniques: list, output_path: Path):
    lines = []
    lines.append('# MITRE ATT&CK Linux — Keyword Review')
    lines.append('')
    lines.append('**Anleitung:**')
    lines.append('1. Lies die offizielle MITRE-Beschreibung jeder Technik')
    lines.append('2. Trage in der Spalte "Keywords (manuell)" konkrete Linux-Befehle/')
    lines.append('   Strings ein die diese Technik in Log-Dateien hinterlässt')
    lines.append('3. Setze in "Aufnehmen?" ein Ja oder Nein')
    lines.append('4. Gib die ausgefüllte Datei zurück zur Implementierung')
    lines.append('')
    lines.append(f'Bereits implementiert: {len(ALREADY_IMPLEMENTED)} T-Nummern  ')
    lines.append(f'Zu reviewen: {len(techniques)} T-Nummern  ')
    lines.append('')
    lines.append('---')
    lines.append('')

    current_tactic = ''
    for t in techniques:
        tactic = t['tactics'].split(',')[0].strip().upper().replace('-', ' ')
        if tactic != current_tactic:
            current_tactic = tactic
            lines.append(f'## {tactic}')
            lines.append('')

        lines.append(f"### {t['id']} — {t['name']}")
        lines.append('')
        lines.append(f"**Taktik:** {t['tactics']}  ")
        lines.append(f"**MITRE Beschreibung (offiziell):**  ")
        lines.append(f"> {t['description']}")
        lines.append('')
        lines.append('**Keywords (manuell eintragen):**')
        lines.append('```')
        lines.append("# Beispiel: 'sudo su', 'visudo', '/etc/sudoers'")
        lines.append('```')
        lines.append('')
        lines.append('**Aufnehmen?** [ ] Ja  [ ] Nein  [ ] Anpassen')
        lines.append('')
        lines.append('---')
        lines.append('')

    output_path.write_text('\n'.join(lines), encoding='utf-8')
    print(f'Review-Datei erstellt: {output_path}')
    print(f'Gesamt zu reviewen: {len(techniques)} Linux-Techniken')


if __name__ == '__main__':
    base = Path(__file__).parent.parent
    json_path = base / 'data' / 'enterprise-attack-v15.json'
    output_path = base / 'mitre_keyword_review.md'

    if not json_path.exists():
        print(f'FEHLER: {json_path} nicht gefunden')
        exit(1)

    print('Lade enterprise-attack-v15.json...')
    techniques = load_linux_techniques(json_path)
    write_markdown(techniques, output_path)
