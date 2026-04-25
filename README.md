# DFIR Analyse-Pipeline — Vollständiges Technisches Pflichtenheft
 
> **Version:** 3.0 — Claude Code Ready
> **Zielgruppe:** Softwareentwickler (auch ohne Forensik-Kenntnisse)
> **Sprache:** Python 3.11+
> **Plattform:** Ubuntu 22.04 LTS
> **Kapitel:** 1–14 (vollständig)
> **Inhalt:** Alle 38 Parser, MITRE ATT&CK, YARA, Sigma, Datenmodelle, Schemas
 
---
 
 
 
 
 
---
 
# 1. Was ist dieses Projekt? (Für Nicht-Forensiker)
 
 
---
 
 
Dieses Dokument beschreibt den Bau einer automatisierten forensischen Analyse-Pipeline. Forensik bedeutet hier: Ein Ermittler bekommt eine Kopie einer Festplatte (Disk-Image) und muss herausfinden was auf diesem Rechner passiert ist — z.B. ob er gehackt wurde.
 
 
> **Einfache Analogie**
 
>
> Stell dir vor ein Einbrecher war in einem Haus. Die Polizei kommt und muss alles untersuchen:
>
> → Fingerabdrücke sichern (= Artefakte sammeln)
>
> → Zeitlinie erstellen: wer war wann wo (= Timeline)
>
> → Verdächtige Gegenstände markieren (= IOC-Extraktion)
>
> → Beweisprotokoll erstellen (= Chain of Custody)
>
> Deine Pipeline macht genau das — aber automatisch und digital, für einen Rechner statt ein Haus.
 
 
 
## 1.1 Was bekommt das System als Eingabe?
 
 
| Disk-Image (.E01, .dd, .vmdk, .raw) | Eine 1:1 Kopie einer Festplatte. Wie ein ZIP-Archiv der gesamten Festplatte. WIRD NICHT GEMOUNTET — das Tool liest es direkt. |
| --- | --- |
| RAM-Dump (.raw, .dmp, .mem) | Eine Kopie des Arbeitsspeichers zum Zeitpunkt der Sicherung. Enthält laufende Prozesse, Passwörter, Netzwerkverbindungen. |
| Log-Ordner | Ordner mit Log-Dateien (.evtx, syslog, auth.log usw.). Protokolle was auf dem System passiert ist. |
 
 
## 1.2 Was gibt das System aus?
 
 
Nach der Analyse wird automatisch folgender Ordner erstellt:
 
 
```
Forensik-Analyse/
└── output/
    └── 2026/                          ← Jahr (automatisch)
        └── 04_April/                  ← Monat (automatisch)
            └── 22_Mittwoch/           ← Tag (automatisch)
                └── case_20260422_091533/
                    ├── report.pdf            ← Analysebericht für Betreuer
                    ├── chain_of_custody.pdf  ← Rechtliches Beweisprotokoll
                    ├── timesketch_link.txt   ← Link zur interaktiven Timeline
                    ├── pipeline_report.json  ← Maschinenlesbarer Gesamtreport
                    ├── autopsy_status.json   ← Autopsy: lief / übersprungen
                    └── raw/
                        ├── disk_artefakte/   ← Dissect Output
                        ├── memory_artefakte/ ← Volatility 3 Output
                        ├── log_artefakte/    ← Plaso / Hayabusa Output
                        └── autopsy_artefakte/ ← Autopsy Output (falls aktiv)
```
 
 
## 1.3 Wie wird das System gestartet?
 
 
```
# Grundaufruf — nur Disk-Image
python pipeline.py /pfad/zum/image.E01 --output_dir /Forensik/output
 
# Mit RAM-Dump
python pipeline.py /pfad/zum/image.E01 \
    --ram /pfad/zu/memory.raw \
    --output_dir /Forensik/output
 
# Mit RAM-Dump und Logs
python pipeline.py /pfad/zum/image.E01 \
    --ram /pfad/zu/memory.raw \
    --logs /pfad/zu/logs/ \
    --output_dir /Forensik/output
 
# Autopsy erzwingen (auch ohne Bedingung)
python pipeline.py /pfad/zum/image.E01 --output_dir /output --force-autopsy
 
# Autopsy deaktivieren
python pipeline.py /pfad/zum/image.E01 --output_dir /output --no-autopsy
 
# Timesketch-Upload deaktivieren
python pipeline.py /pfad/zum/image.E01 --output_dir /output --no-timesketch
```
 
 
 
 
 
---
 
# 2. Projektstruktur — Ordner und Dateien
 
 
---
 
 
So soll das Projekt auf der Festplatte des Entwicklers strukturiert sein. Alle Ordner und Dateien sind vollständig — inkl. aller 38 Parser, MITRE ATT&CK, YARA und Sigma:
 
 
```
dfir_pipeline/
├── pipeline.py                    ← Haupt-Einstiegspunkt (CLI)
├── config.yaml                    ← Konfigurationsdatei
├── requirements.txt               ← Alle Python-Abhängigkeiten (Kapitel 14)
├── docker-compose.yml             ← Timesketch + Elasticsearch
├── README.md                      ← Schnellstart-Anleitung
│
├── stages/                        ← Eine Datei pro Pipeline-Stufe
│   ├── __init__.py
│   ├── stage01_detection.py       ← Dateierkennung + Hash
│   ├── stage02_memory.py          ← UAC + Volatility 3
│   ├── stage02_5_profiling.py     ← System-Profiling
│   ├── stage03_logs.py            ← Log-Parsing + Parser-Router (Kapitel 13)
│   ├── stage04_disk.py            ← Dissect + Zimmerman
│   ├── stage04_1_autopsy.py       ← Autopsy (konditionell)
│   ├── stage04_5_ioc.py           ← IOC-Extraktion
│   ├── stage05_tsk.py             ← TSK Fallback
│   ├── stage06_normalize.py       ← Datennormalisierung
│   ├── stage07_antiforensics.py   ← Anti-Forensics + YARA (Kapitel 12)
│   ├── stage08_ml.py              ← Isolation Forest
│   ├── stage09_mitre.py           ← MITRE ATT&CK Mapping (Kapitel 11)
│   ├── stage10_ai.py              ← KI-Anreicherung
│   ├── stage11_quality.py         ← Fehler-Handling
│   └── stage12_export.py          ← Export + Report PDF
│
├── parsers/                       ← Alle 38 Log-Parser (Kapitel 10)
│   ├── __init__.py                ← Importiert alle Parser
│   ├── base_parser.py             ← Basis-Klasse (alle erben davon)
│   │
│   ├── # Gruppe 1: Linux System-Logs (8 Parser)
│   ├── syslog_parser.py           ← /var/log/syslog, messages
│   ├── auth_parser.py             ← /var/log/auth.log, secure
│   ├── journald_parser.py         ← /var/log/journal/*.journal (binaer)
│   ├── kern_parser.py             ← /var/log/kern.log, dmesg
│   ├── boot_parser.py             ← /var/log/boot.log
│   ├── daemon_parser.py           ← /var/log/daemon.log
│   ├── wtmp_parser.py             ← /var/log/wtmp (binaer)
│   ├── lastlog_parser.py          ← /var/log/lastlog (binaer)
│   │
│   ├── # Gruppe 2: Paket-Manager (5 Parser)
│   ├── dpkg_parser.py             ← /var/log/dpkg.log (Debian/Ubuntu)
│   ├── apt_parser.py              ← /var/log/apt/history.log
│   ├── yum_parser.py              ← /var/log/yum.log (RHEL/CentOS)
│   ├── dnf_parser.py              ← /var/log/dnf.log (Fedora/RHEL8+)
│   ├── pacman_parser.py           ← /var/log/pacman.log (Arch)
│   │
│   ├── # Gruppe 3: Web-Server (4 Parser)
│   ├── apache_access_parser.py    ← access.log (Apache/Ubuntu/RHEL)
│   ├── apache_error_parser.py     ← error.log (Apache)
│   ├── nginx_access_parser.py     ← /var/log/nginx/access.log
│   ├── nginx_error_parser.py      ← /var/log/nginx/error.log
│   │
│   ├── # Gruppe 4: Datenbanken (3 Parser)
│   ├── mysql_parser.py            ← /var/log/mysql/error.log
│   ├── postgresql_parser.py       ← /var/log/postgresql/*.log
│   ├── mongodb_parser.py          ← /var/log/mongodb/mongod.log
│   │
│   ├── # Gruppe 5: Security (4 Parser)
│   ├── audit_parser.py            ← /var/log/audit/audit.log
│   ├── fail2ban_parser.py         ← /var/log/fail2ban.log
│   ├── ufw_parser.py              ← /var/log/ufw.log
│   ├── cron_parser.py             ← /var/log/cron, cron.log
│   │
│   ├── # Gruppe 6: User-Aktivitaet (4 Parser)
│   ├── bash_history_parser.py     ← /home/*/.bash_history
│   ├── zsh_history_parser.py      ← /home/*/.zsh_history
│   ├── fish_history_parser.py     ← /home/*/.local/share/fish/fish_history
│   ├── utmp_parser.py             ← /var/run/utmp (binaer)
│   │
│   ├── # Gruppe 7: Netzwerk & Dienste (5 Parser)
│   ├── ssh_parser.py              ← Aus auth.log extrahiert
│   ├── postfix_parser.py          ← /var/log/mail.log
│   ├── ftp_parser.py              ← /var/log/vsftpd.log
│   ├── samba_parser.py            ← /var/log/samba/
│   ├── openvpn_parser.py          ← /var/log/openvpn.log
│   │
│   ├── # Gruppe 8: Container & Cloud (5 Parser)
│   ├── docker_parser.py           ← /var/lib/docker/containers/*
│   ├── containerd_parser.py       ← /var/log/containerd.log
│   ├── iis_parser.py              ← C:/inetpub/logs/ (Windows-Images)
│   ├── evtx_parser.py             ← *.evtx via Hayabusa
│   └── plaso_parser.py            ← Fallback fuer alle anderen Formate
│
├── models/                        ← Datenmodelle (Klassen)
│   ├── __init__.py
│   ├── pipeline_context.py        ← Haupt-Datencontainer (alle Felder)
│   ├── event.py                   ← ForensicEvent (ein Log-Ereignis)
│   ├── ioc.py                     ← IOC-Datenmodell
│   └── chain_of_custody.py        ← CoC-Datenmodell
│
├── utils/                         ← Hilfsfunktionen
│   ├── __init__.py
│   ├── hashing.py                 ← SHA256/MD5 Berechnung
│   ├── timestamp.py               ← Timestamp-Normalisierung → UTC
│   ├── file_detection.py          ← Datei-Format-Erkennung
│   ├── logger.py                  ← Logging-Konfiguration
│   └── event_store.py             ← DuckDB Event-Store (RAM-Entlastung, v3.1)
│
├── data/                          ← Statische Daten (einmalig herunterladen)
│   ├── enterprise-attack-v15.json ← MITRE ATT&CK v15 (ca. 80 MB)
│   ├── yara-rules/                ← YARA Community + Signature-Base
│   │   ├── community/             ← github.com/Yara-Rules/rules
│   │   │   ├── malware/
│   │   │   ├── antidebug_antivm/
│   │   │   └── exploit_kits/
│   │   ├── signature-base/        ← github.com/Neo23x0/signature-base
│   │   └── custom/                ← Eigene Anti-Forensics-Regeln
│   │       ├── timestomping.yar
│   │       └── log_wiping.yar
│   └── sigma-rules/               ← github.com/SigmaHQ/sigma
│       └── rules/
│           └── windows/           ← Fuer Windows-Images (EVTX)
│
├── output/                        ← Automatisch erstellt (leer lassen)
│   └── 2026/                      ← Jahr (auto)
│       └── 04_April/              ← Monat (auto)
│           └── 22_Mittwoch/       ← Tag (auto)
│               └── case_*/        ← Case (auto)
│
└── tests/                         ← Unit Tests
    ├── test_stage01.py
    ├── test_stage03.py
    ├── test_parsers.py             ← Tests fuer alle 38 Parser
    ├── test_mitre.py               ← Tests fuer MITRE-Mapping
    └── test_ioc.py                 ← Tests fuer IOC-Extraktion
```
 
 
 
 
 
---
 
# 3. Datenmodell — Was zwischen den Stufen fließt
 
 
---
 
 
Jede Stufe bekommt ein PipelineContext-Objekt und gibt dasselbe Objekt (angereichert) weiter. Das ist das zentrale Datenmodell der gesamten Pipeline.
 
 
## 3.1 PipelineContext — Haupt-Datencontainer
 
 
```
# models/pipeline_context.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
 
@dataclass
class PipelineContext:
    # ── Eingabe ──────────────────────────────────────────
    disk_image_path:   Optional[Path] = None   # Pfad zum Disk-Image
    ram_dump_path:     Optional[Path] = None   # Pfad zum RAM-Dump (optional)
    logs_dir_path:     Optional[Path] = None   # Pfad zum Log-Ordner (optional)
    output_dir:        Path = Path('./output') # Ausgabe-Ordner
    case_dir:          Optional[Path] = None   # Wird in Stufe 1 gesetzt
 
    # ── Stage 1: Dateierkennung ───────────────────────────
    file_type:         str = ''                # 'E01', 'DD', 'VMDK', 'RAW'
    file_size_gb:      float = 0.0
    sha256:            str = ''
    md5:               str = ''
 
    # ── Stage 2: Memory ───────────────────────────────────
    memory_results:    Dict[str, Any] = field(default_factory=dict)
    # Enthält: processes, network, bash_history, modules, malfind
 
    # ── Stage 2.5: System-Profiling ───────────────────────
    os_family:         str = ''   # 'debian', 'rhel', 'arch', 'alpine'
    os_name:           str = ''   # 'Ubuntu 22.04 LTS'
    kernel_version:    str = ''   # '5.15.0-91-generic'
    hostname:          str = ''
    timezone:          str = 'UTC'
    log_paths:         Dict[str, Path] = field(default_factory=dict)
    # log_paths wird von Stage 2.5 gesetzt und von Stage 3 genutzt
 
    # ── Stage 3: Log-Parsing ──────────────────────────────
    events:            List['ForensicEvent'] = field(default_factory=list)  # leer nach v3.1
    events_db_path:    Optional[Path] = None          # Pfad zur events.db (DuckDB)
    parser_stats:      Dict[str, int] = field(default_factory=dict)  # Events pro Parser
    total_log_lines:   int = 0
    parsed_events:     int = 0
 
    # ── Stage 4: Disk ─────────────────────────────────────
    disk_artifacts:    Dict[str, Any] = field(default_factory=dict)
    image_count:       int = 0
    email_db_found:    bool = False
    encrypted_count:   int = 0
    unknown_ext_count: int = 0
    dissect_empty:     bool = False  # True = TSK Fallback nötig
 
    # ── Stage 4.1: Autopsy ────────────────────────────────
    autopsy_ran:       bool = False
    autopsy_reason:    str = ''      # Warum gestartet / übersprungen
    autopsy_results:   Dict[str, Any] = field(default_factory=dict)
 
    # ── Stage 4.5: IOC-Extraktion ─────────────────────────
    iocs:              List['IOC'] = field(default_factory=list)
    ioc_quality:       str = 'HOCH' # 'HOCH' oder 'MITTEL' (TSK-Fallback)
 
    # ── Stage 5: TSK Fallback ─────────────────────────────
    tsk_fallback_used: bool = False
    tsk_results:       Dict[str, Any] = field(default_factory=dict)
 
    # ── Stage 6: Normalisierung ───────────────────────────
    normalized_events: List['ForensicEvent'] = field(default_factory=list)
 
    # ── Stage 7: Anti-Forensics ───────────────────────────
    antiforensics_hits: List[Dict] = field(default_factory=list)
 
    # ── Stage 8: ML ───────────────────────────────────────
    anomalies:         List['ForensicEvent'] = field(default_factory=list)
    anomaly_scores:    List[float] = field(default_factory=list)
 
    # ── Stage 9: MITRE ────────────────────────────────────
    mitre_hits:        List[Dict] = field(default_factory=list)
 
    # ── Stage 10: KI ──────────────────────────────────────
    enriched_summary:  str = ''
 
    # ── Stage 11: Qualität ────────────────────────────────
    stage_errors:      Dict[str, str] = field(default_factory=dict)
    stage_status:      Dict[str, str] = field(default_factory=dict)
 
    # ── Chain of Custody ──────────────────────────────────
    coc:               Optional['ChainOfCustody'] = None
    start_time:        datetime = field(default_factory=datetime.now)
```
 
 
## 3.2 ForensicEvent — Ein einzelnes forensisches Ereignis
 
 
```
# models/event.py
@dataclass
class ForensicEvent:
    timestamp:    datetime          # UTC — immer UTC!
    source:       str               # 'syslog', 'evtx', 'dissect', 'volatility'
    event_type:   str               # 'login', 'process', 'network', 'file'
    message:      str               # Rohe Log-Nachricht
    user:         Optional[str] = None
    ip:           Optional[str] = None
    process:      Optional[str] = None
    file_path:    Optional[str] = None
    severity:     str = 'info'      # 'info', 'low', 'medium', 'high', 'critical'
    anomaly_score: float = 0.0      # 0.0 = normal, 1.0 = sehr verdächtig
    mitre_tags:   List[str] = field(default_factory=list)  # ['T1053.003']
    # raw-Feld entfernt (v3.1) — spart ~800 MB bei 3,4 Mio Events
```
 
 
## 3.3 IOC — Indicator of Compromise
 
 
```
# models/ioc.py
@dataclass
class IOC:
    type:       str    # 'ip', 'domain', 'hash_md5', 'hash_sha256',
                       # 'email', 'cve', 'registry_key', 'process_name'
    value:      str    # Der eigentliche Wert, z.B. '192.168.1.99'
    source:     str    # Woher: 'dissect', 'hayabusa', 'autopsy', 'tsk'
    confidence: float  # 0.0 bis 1.0
    context:    str    # Zusätzlicher Kontext
    timestamp:  Optional[datetime] = None
```
 
 
 
 
 
---
 
# 4. Alle Stufen im Überblick
 
 
---
 
 
| Stufe | Bezeichnung | Funktion | Tools |
| --- | --- | --- | --- |
| 1 | Automatische Dateierkennung | Dateityp erkennen, SHA256/MD5 berechnen, Chain of Custody starten | python-magic, hashlib |
| 2 | UAC + Volatility 3 | RAM-Dump analysieren, Live-Artefakte sammeln | UAC, Volatility 3 |
| 2.5 | System-Profiling | Linux-Familie, Kernel, Distro, Log-Pfade bestimmen | dissect, os-release |
| 3 | Log-Parsing (38 Parser) | Alle Log-Formate parsen, relevante Events filtern | Plaso, Hayabusa, custom |
| 3.1 | Parser-Architektur | Format-Erkennung und automatisches Parser-Routing | python-magic, regex |
| 3.2 | 38 Linux-Log-Parser | Syslog, auth.log, Journald, Apache, SSH, Cron, ... | custom Python Parser |
| 4 | Dissect + Zimmerman Tools | Disk-Image Artefakte extrahieren | Dissect, Zimmerman (Wine) |
| 4.1 | Autopsy (konditionell) | Startet nur wenn mind. eine Bedingung erfüllt ist | Autopsy Headless (Java) |
| 4.1.1 | Bedingung 1: Bilder > 100 | EXIF, GPS-Daten, Thumbnails analysieren | Autopsy EXIF Parser |
| 4.1.2 | Bedingung 2: E-Mail-DB gefunden | PST / OST / MBOX parsen, verdächtige E-Mails filtern | Autopsy Email Parser |
| 4.1.3 | Bedingung 3: Verschlüsselte Dateien | Verschlüsselungs-Typ erkennen und dokumentieren | Autopsy Encryption |
| 4.1.4 | Bedingung 4: Unbekannte Typen > 50 | Hash-Datenbank Abgleich (NSRL) | Autopsy Hash Lookup |
| 4.1.5 | Bedingung 5: Nichts zutrifft | Autopsy wird übersprungen — spart ca. 45 Minuten | — (übersprungen) |
| 4.5 | IOC-Extraktion | IPs, Domains, Hashes, CVEs aus allen Artefakten extrahieren | regex, yara, custom |
| 5 | TSK Fallback | Falls Dissect leer: TSK übernimmt Dateisystem-Analyse | The Sleuth Kit |
| 5.1 | Multi-Partition-Analyse | MBR/GPT Partitionstabellen lesen, jede Partition einzeln | TSK mmls, mmcat |
| 6 | Datennormalisierung | Alle Timestamps → UTC, alle Felder → einheitliches Schema | pandas, dateutil |
| 7 | Anti-Forensics-Erkennung | Timestomping, Log-Löschung, Rootkit-Indikatoren | custom, yara |
| 8 | ML-Anomalieerkennung | Isolation Forest markiert statistische Ausreißer | scikit-learn |
| 9 | MITRE ATT&CK Mapping | 80+ Techniken aus ATT&CK v15 automatisch mappen | attackcti, custom |
| 10 | KI-Vorverarbeitung | Ergebnisse anreichern und zusammenfassen | custom NLP |
| 11 | Fehler-Handling & Qualität | Alle Stufen-Fehler dokumentieren, Qualitätsbewertung | custom |
| 12 | Export & Archivierung | report.pdf, chain_of_custody.pdf, Timesketch Upload | Timesketch API, reportlab |
 
 
 
 
 
---
 
# 5. Stufen — Vollständige Detailbeschreibung
 
 
---
 
 
## Stufe 1 — Automatische Dateierkennung
 
 
> **Aufgabe dieser Stufe**
 
>
> Erkennt automatisch welcher Dateityp übergeben wurde
>
> Berechnet SHA256 und MD5 Hash — dieser MUSS am Ende identisch sein
>
> Startet die Chain of Custody
>
> Setzt ctx.file_type, ctx.sha256, ctx.md5, ctx.file_size_gb
>
> Erstellt die komplette Ausgabe-Ordnerstruktur
 
 
 
### Unterstützte Eingabeformate:
 
 
| Format | Erkennung | Beschreibung |
| --- | --- | --- |
| E01 / EWF | python-magic: 'EWF' | Expert Witness Format — häufigster forensischer Standard |
| DD / RAW | python-magic: 'data' | Rohes Disk-Image, 1:1 Kopie |
| VMDK | python-magic: 'VMware' | VMware Virtual Disk |
| VHDX | python-magic: 'Microsoft' | Hyper-V Virtual Disk |
| QCoW2 | python-magic: 'QEMU' | QEMU/KVM Virtual Disk |
| AFF | python-magic: 'AFF' | Advanced Forensics Format |
 
 
### Implementierung:
 
 
```
# stages/stage01_detection.py
import magic
import hashlib
from pathlib import Path
from models.pipeline_context import PipelineContext
from datetime import datetime
 
def run(ctx: PipelineContext) -> PipelineContext:
    path = ctx.disk_image_path
 
    # 1. Dateityp erkennen
    mime = magic.from_file(str(path), mime=True)
    raw  = magic.from_file(str(path))
    ctx.file_type = detect_format(raw)   # 'E01', 'DD', 'VMDK' ...
 
    # 2. Dateigröße
    ctx.file_size_gb = path.stat().st_size / (1024**3)
 
    # 3. Hash berechnen (SHA256 + MD5)
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
            md5.update(chunk)
    ctx.sha256 = sha256.hexdigest()
    ctx.md5    = md5.hexdigest()
 
    # 4. Ausgabe-Ordnerstruktur erstellen
    ctx.case_dir = create_case_dir(ctx.output_dir)
 
    # 5. Chain of Custody starten
    ctx.coc = ChainOfCustody(
        file_name   = path.name,
        sha256      = ctx.sha256,
        md5         = ctx.md5,
        size_gb     = ctx.file_size_gb,
        start_time  = datetime.utcnow(),
    )
 
    return ctx
 
def create_case_dir(output_dir: Path) -> Path:
    now   = datetime.now()
    tage  = ['Montag','Dienstag','Mittwoch','Donnerstag','Freitag','Samstag','Sonntag']
    monate= ['','Januar','Februar','März','April','Mai','Juni',
             'Juli','August','September','Oktober','November','Dezember']
    jahr  = now.strftime('%Y')
    monat = f"{now.month:02d}_{monate[now.month]}"
    tag   = f"{now.day:02d}_{tage[now.weekday()]}"
    case  = f"case_{now.strftime('%Y%m%d_%H%M%S')}"
    case_dir = output_dir / jahr / monat / tag / case
    for sub in ['raw/disk_artefakte','raw/memory_artefakte',
                'raw/log_artefakte','raw/autopsy_artefakte']:
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    return case_dir
```
 
 
## Stufe 2 — UAC + Volatility 3 (RAM-Analyse)
 
 
> **Aufgabe dieser Stufe**
 
>
> UAC sammelt Live-Artefakte falls ein Live-System analysiert wird
>
> Volatility 3 analysiert RAM-Dumps — läuft NUR wenn --ram angegeben wurde
>
> Beide Ergebnisse werden in ctx.memory_results gespeichert
>
> Falls kein RAM-Dump vorhanden: Stufe wird übersprungen (kein Fehler)
 
 
 
### Volatility 3 Plugins — vollständige Liste:
 
 
| Plugin | Ausgabe | Wichtig weil |
| --- | --- | --- |
| linux.pslist | Liste aller Prozesse | Zeigt was lief — auch versteckte |
| linux.pstree | Prozess-Baum (Eltern/Kind) | Zeigt welcher Prozess welchen startete |
| linux.netstat | Netzwerk-Verbindungen | Zeigt zu welchen IPs verbunden wurde |
| linux.bash | Bash-History aus RAM | Zeigt eingegebene Befehle |
| linux.malfind | Verdächtige Speicherbereiche | Erkennt Code-Injection in RAM |
| linux.modules | Kernel-Module | Zeigt geladene Treiber / Rootkits |
| linux.capabilities | Prozess-Rechte | Zeigt wer welche Rechte hatte |
| linux.envars | Umgebungsvariablen | Zeigt Konfiguration der Prozesse |
| linux.sockstat | Socket-Statistiken | Netzwerk-Status im RAM |
| linux.lsof | Offene Dateien | Welche Dateien waren geöffnet |
 
 
### Fehlerverhalten:
 
 
## Stufe 2.5 — System-Profiling
 
 
> **Warum diese Stufe so früh?**
 
>
> Jede Linux-Distribution speichert Logs an anderen Orten
>
> Ubuntu: /var/log/syslog — CentOS: /var/log/messages — Alpine: /var/log/messages
>
> Ohne System-Profiling würden die Parser in Stufe 3 blind suchen
>
> ctx.log_paths wird hier gesetzt und von Stufe 3 direkt genutzt
 
 
 
### Erkannte Linux-Familien:
 
 
| OS-Familie | Erkennungsmerkmal | Log-Pfade (Beispiele) |
| --- | --- | --- |
| Debian / Ubuntu | /etc/debian_version | /var/log/syslog, /var/log/auth.log |
| RHEL / CentOS | /etc/redhat-release | /var/log/messages, /var/log/secure |
| Arch Linux | /etc/arch-release | /var/log/pacman.log, journald |
| Alpine Linux | /etc/alpine-release | /var/log/messages, /var/log/auth.log |
| Kali Linux | ID=kali in /etc/os-release | /var/log/syslog, /var/log/auth.log |
| Unbekannt | Keines der obigen | Alle Standard-Pfade durchsuchen |
 
 
```
# stages/stage02_5_profiling.py
def detect_os_family(ctx: PipelineContext) -> PipelineContext:
    # Dissect wird genutzt um /etc/os-release aus dem Image zu lesen
    # OHNE das Image zu mounten
    os_release = read_file_from_image(ctx.disk_image_path, '/etc/os-release')
 
    if 'debian' in os_release or 'ubuntu' in os_release:
        ctx.os_family = 'debian'
        ctx.log_paths = {
            'syslog':   Path('/var/log/syslog'),
            'auth':     Path('/var/log/auth.log'),
            'kern':     Path('/var/log/kern.log'),
            'dpkg':     Path('/var/log/dpkg.log'),
        }
    elif 'rhel' in os_release or 'centos' in os_release:
        ctx.os_family = 'rhel'
        ctx.log_paths = {
            'syslog':   Path('/var/log/messages'),
            'auth':     Path('/var/log/secure'),
            'yum':      Path('/var/log/yum.log'),
        }
    # ... weitere Familien
    return ctx
```
 
 
## Stufe 3 — Log-Parsing (38 Parser)
 
 
> **Aufgabe dieser Stufe**
 
>
> stage03_logs.py ist der Manager — er koordiniert alle 38 Parser
>
> Für jede Log-Datei im Image wird genau EIN Parser aufgerufen (kein Überschneiden)
>
> Reihenfolge: Spezifischer Parser zuerst → Plaso als letzter Fallback
>
> Plaso, Hayabusa und Journald sind Teil der 38 Parser — keine separaten Tools
>
> Plaso = Parser 38 (Fallback), Hayabusa = wird von EVTXParser aufgerufen, Journald = Parser 3
>
> Ergebnis (v3.1): Events werden in DuckDB-Datei (events.db) gespeichert — ctx.events bleibt leer um RAM zu sparen
 
 
 
> **Wie der Parser-Router funktioniert**
 
>
> 1. stage03_logs.py findet alle Log-Dateien im Image
>
> 2. Für jede Datei: Parser-Router fragt alle 38 Parser der Reihe nach
>
> 3. Erster Parser der can_parse() = True zurückgibt wird aufgerufen
>
> 4. break — kein zweiter Parser wird aufgerufen (kein Überschneiden)
>
> 5. Kein Parser passt → PlasaFallbackParser als letzter Ausweg
>
> 6. Alle Events werden in 1000er-Batches in DuckDB (events.db) geschrieben — nie komplett im RAM
 
 
 
### Parser-Basis-Klasse — alle 38 Parser erben davon:
 
 
```
# parsers/base_parser.py
from abc import ABC, abstractmethod
from models.event import ForensicEvent
from pathlib import Path
from typing import List
 
class BaseParser(ABC):
    name: str = ''           # z.B. 'syslog'
    file_pattern: str = ''   # z.B. 'syslog*'
 
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        # Prüft ob dieser Parser die Datei lesen kann
        pass
 
    @abstractmethod
    def parse(self, file_path: Path) -> List[ForensicEvent]:
        # Liest die Datei und gibt ForensicEvent-Liste zurück
        pass
 
    def parse_timestamp(self, raw: str) -> datetime:
        # Timestamp-Parsing — IMMER UTC zurückgeben
        from utils.timestamp import to_utc
        return to_utc(raw)
```
 
 
### Alle 38 Parser im Überblick (vollständige Implementierung in Kapitel 10):
 
 
| Parser | Datei / Quelle | Was wird geparst |
| --- | --- | --- |
| SyslogParser | syslog, messages | System-Meldungen (Debian/Ubuntu/RHEL) |
| AuthLogParser | auth.log, secure | Login-Versuche, SSH, sudo, PAM |
| JournaldParser | journal/*.journal (binaer) | systemd Binary Journal (moderne Linux) |
| KernLogParser | kern.log, dmesg | Kernel-Meldungen, OOM, Panic |
| BootLogParser | boot.log | Boot-Sequenz, OK/FAILED Status |
| DaemonLogParser | daemon.log | Daemon-Start/Stop Events |
| WtmpParser | wtmp (binaer) | Login-History (struct-Format) |
| LastlogParser | lastlog (binaer) | Letzter Login pro User |
| DpkgParser | dpkg.log | Paket-Installationen (Debian/Ubuntu) |
| AptHistoryParser | apt/history.log | APT-Befehle und Transaktionen |
| YumParser | yum.log | Paket-Installationen (RHEL/CentOS) |
| DnfParser | dnf.log, dnf.rpm.log | Paket-Installationen (Fedora/RHEL8+) |
| PacmanParser | pacman.log | Paket-Installationen (Arch Linux) |
| ApacheAccessParser | access.log, access_log | HTTP-Requests, Status-Codes |
| ApacheErrorParser | error.log, error_log | Apache-Fehler und Warnungen |
| NginxAccessParser | nginx/access.log | HTTP-Requests (Nginx) |
| NginxErrorParser | nginx/error.log | Nginx-Fehler und Warnungen |
| MySQLErrorParser | mysql/error.log | MySQL/MariaDB Datenbankfehler |
| PostgreSQLParser | postgresql-*.log | PostgreSQL Datenbankevents |
| MongoDBParser | mongod.log (JSON+Text) | MongoDB Events (neu+alt Format) |
| AuditParser | audit/audit.log | Linux Audit Framework Syscalls |
| Fail2BanParser | fail2ban.log | Brute-Force Ban/Unban Events |
| UFWParser | ufw.log | Firewall Block/Allow Events |
| CronParser | cron, cron.log | Geplante Aufgaben, verdächtige CMDs |
| BashHistoryParser | .bash_history | Shell-Befehle mit Timestamp |
| ZshHistoryParser | .zsh_history | Zsh Shell-Befehle |
| FishHistoryParser | fish_history | Fish Shell-Befehle (YAML-Format) |
| UtmpParser | utmp (binaer) | Aktuelle Sessions (identisch wtmp) |
| SSHParser | aus auth.log extrahiert | SSH Login/Fail/Tunnel/X11 |
| PostfixMailParser | mail.log, maillog | Mail-Zustellungen und Fehler |
| FTPParser | vsftpd.log, proftpd.log | FTP Login/Upload/Download |
| SambaParser | samba/log.* | SMB/CIFS Netzwerkfreigaben |
| OpenVPNParser | openvpn.log | VPN-Verbindungen und Fehler |
| DockerParser | containers/*-json.log | Container-Logs (JSON-Lines) |
| ContainerdParser | containerd.log | Container-Runtime Events |
| IISLogParser | u_ex*.log (Windows) | IIS Web-Server Requests (W3C) |
| EVTXParser | *.evtx via Hayabusa | Windows Event Logs + Sigma-Regeln |
| PlasaFallbackParser | alle unbekannten Formate | Letzter Fallback — Plaso/log2timeline |
 
 
## Stufe 4 — Dissect + Zimmerman Tools
 
 
> **Aufgabe dieser Stufe**
 
>
> Dissect: Liest das Disk-Image DIREKT (kein Mounten nötig) und extrahiert Artefakte
>
> Zimmerman Tools: Parst Windows-Artefakte falls das Image ein Windows-System enthält
>
> Setzt ctx.dissect_empty = True falls Dissect nichts findet (TSK Fallback nötig)
>
> Setzt ctx.image_count, ctx.email_db_found, ctx.encrypted_count für Autopsy-Trigger
 
 
 
### Dissect — extrahierte Artefakte:
 
 
| Artefakt | Dissect-Funktion | Forensische Bedeutung |
| --- | --- | --- |
| Master File Table | target-query -f mft | Alle Dateien inkl. gelöschter (NTFS) |
| Registry Hives | target-query -f registry | Windows-Konfiguration, Autostart |
| Prefetch-Dateien | target-query -f prefetch | Welche Programme wann liefen |
| LNK-Dateien | target-query -f lnk | Zuletzt geöffnete Dateien |
| Shellbags | target-query -f shellbags | Besuchte Ordner |
| Jump Lists | target-query -f jumplist | Zuletzt verwendete Dateien pro App |
| Browser-History | target-query -f browser | Besuchte Webseiten |
| SSH-Keys | target-query -f ssh | SSH known_hosts, authorized_keys |
| Bash-History | target-query -f bash | Eingegebene Befehle |
| Crontab | target-query -f crontab | Geplante Aufgaben |
| Benutzerkonten | target-query -f users | Alle Benutzer auf dem System |
| Netzwerk-Config | target-query -f network | IP-Adressen, Interfaces |
| SRUM-Datenbank | target-query -f srum | Ressourcen-Nutzung (Windows) |
| Amcache | target-query -f amcache | Ausgeführte Programme (Windows) |
 
 
## Stufe 4.1 — Autopsy (konditionell)
 
 
> **Was ist Autopsy?**
 
>
> Autopsy ist ein forensisches Analyse-Tool (Open Source, Apache 2.0 Lizenz)
>
> Es läuft im --headless Modus — kein Fenster, kein GUI, vollständig automatisierbar
>
> Python startet Autopsy als Subprocess und liest den XML-Report ein
>
> Benötigt Java (JRE) — muss installiert sein: apt install default-jre autopsy
>
> Laufzeit: ca. 45 Minuten bei einem 50GB Image — deshalb nur konditionell
 
 
 
### Entscheidungslogik — wann startet Autopsy?
 
 
```
# stages/stage04_1_autopsy.py
def should_run_autopsy(ctx: PipelineContext, force: bool = False) -> tuple[bool, str]:
    if force:
        return True, 'Manuell erzwungen (--force-autopsy)'
 
    # Bedingung 4.1.1 — Mehr als 100 Bilddateien
    if ctx.image_count > 100:
        return True, f'Bedingung 4.1.1: {ctx.image_count} Bilddateien gefunden'
 
    # Bedingung 4.1.2 — E-Mail-Datenbank gefunden
    if ctx.email_db_found:
        return True, 'Bedingung 4.1.2: E-Mail-Datenbank gefunden (PST/OST/MBOX)'
 
    # Bedingung 4.1.3 — Verschlüsselte Dateien
    if ctx.encrypted_count > 0:
        return True, f'Bedingung 4.1.3: {ctx.encrypted_count} verschlüsselte Dateien'
 
    # Bedingung 4.1.4 — Viele unbekannte Dateitypen
    if ctx.unknown_ext_count > 50:
        return True, f'Bedingung 4.1.4: {ctx.unknown_ext_count} unbekannte Dateitypen'
 
    # Bedingung 4.1.5 — Nichts trifft zu
    return False, 'Bedingung 4.1.5: Keine Bedingung erfüllt — Autopsy übersprungen'
```
 
 
### Autopsy Headless — CLI-Aufruf:
 
 
```
# Schritt 1: Case erstellen
subprocess.run(['autopsy', '--headless', '--createCase', str(case_dir),
    '--caseName', 'dfir_case', '--caseType', 'single'])
 
# Schritt 2: Image hinzufügen
subprocess.run(['autopsy', '--headless', '--addDataSource',
    '--dataSourcePath', str(ctx.disk_image_path),
    '--dataSourceType', 'IMAGE', '--caseDir', str(case_dir)])
 
# Schritt 3: Ingest-Module ausführen
subprocess.run(['autopsy', '--headless', '--runIngest',
    '--ingestConfig', str(ingest_config), '--caseDir', str(case_dir)])
 
# Schritt 4: Report generieren
subprocess.run(['autopsy', '--headless', '--generateReport',
    '--reportType', 'XML', '--reportDir', str(report_dir),
    '--caseDir', str(case_dir)])
 
# Schritt 5: XML-Report einlesen
results = parse_autopsy_xml(report_dir / 'report.xml')
ctx.autopsy_results = results
ctx.autopsy_ran = True
```
 
 
## Stufe 4.5 — IOC-Extraktion
 
 
> **Warum hier (nicht am Ende)?**
 
>
> IOC-Extraktion MUSS vor dem MITRE ATT&CK Mapping (Stufe 9) laufen
>
> Das MITRE-Mapping nutzt die extrahierten IOCs um Techniken zuzuordnen
>
> Quellen: Dissect + Zimmerman + Autopsy (falls gelaufen) + Log-Events
>
> Falls TSK-Fallback: ioc_quality wird auf 'MITTEL' gesetzt (weniger Quellen)
 
 
 
### Extrahierte IOC-Typen mit Regex-Mustern:
 
 
| IOC-Typ | Regex-Muster (vereinfacht) | Beispiel |
| --- | --- | --- |
| IPv4-Adresse | \b(?:\d{1,3}\.){3}\d{1,3}\b | 192.168.1.99 |
| IPv6-Adresse | ([0-9a-fA-F]{1,4}:){7}... | 2001:db8::1 |
| Domain | [a-zA-Z0-9.-]+\.[a-zA-Z]{2,} | evil.example.com |
| URL | https?://[^\s]+ | http://malware.com/payload |
| MD5-Hash | [0-9a-fA-F]{32} | d41d8cd98f00b204e980... |
| SHA256-Hash | [0-9a-fA-F]{64} | e3b0c44298fc1c149afb... |
| E-Mail | [a-zA-Z0-9.]+@[a-zA-Z0-9.]+ | attacker@evil.com |
| CVE-Nummer | CVE-\d{4}-\d{4,7} | CVE-2021-44228 |
| Registry-Key | HKEY_[A-Z_]+\\[^\n]+ | HKEY_LOCAL_MACHINE\... |
 
 
## Stufe 5 — TSK Fallback + Multi-Partition-Analyse
 
 
> **Wann wird TSK aktiv?**
 
>
> ctx.dissect_empty == True (Dissect hat nichts gefunden)
>
> Typische Ursachen: XFS-Dateisystem, Btrfs, korruptes Image, unbekanntes Format
>
> TSK übernimmt dann die komplette Dateisystem-Analyse
>
> ctx.tsk_fallback_used wird auf True gesetzt
>
> ctx.ioc_quality wird auf 'MITTEL' herabgesetzt
 
 
 
### TSK-Tools die verwendet werden:
 
 
| TSK-Tool | Funktion | Ausgabe |
| --- | --- | --- |
| mmls | Partitionstabelle lesen | Liste aller Partitionen mit Offset |
| fsstat | Dateisystem-Info | Dateisystem-Typ, Größe, Cluster |
| fls | Dateien und Ordner listen | Alle Dateien inkl. gelöschter |
| icat | Datei-Inhalt extrahieren | Rohdaten einer bestimmten Datei |
| ils | Inode-Liste | Alle Inodes inkl. freier |
| tsk_recover | Gelöschte Dateien wiederherstellen | Wiederhergestellte Dateien |
| mactime | MAC-Timeline erstellen | Zeitlinie aller Dateizugriffe |
 
 
### Multi-Partition-Analyse (5.1) — läuft immer:
 
 
```
# stages/stage05_tsk.py
def analyse_partitions(ctx: PipelineContext):
    # mmls: Partitionstabelle lesen
    result = subprocess.run(
        ['mmls', str(ctx.disk_image_path)],
        capture_output=True, text=True
    )
    partitions = parse_mmls_output(result.stdout)
 
    for partition in partitions:
        # Jede Partition einzeln analysieren
        offset = partition['start']
        fs_type = detect_filesystem(ctx.disk_image_path, offset)
 
        if fs_type in ['ntfs', 'fat32', 'exfat', 'ext4', 'ext3']:
            analyse_partition_tsk(ctx, offset, fs_type)
        elif fs_type == 'xfs':
            analyse_partition_xfs(ctx, offset)  # xfs_db als Fallback
        else:
            log.warning(f'Unbekanntes Dateisystem: {fs_type} — übersprungen')
```
 
 
## Stufe 6 — Datennormalisierung
 
 
> **Warum ist das so wichtig?**
 
>
> Syslog verwendet: 'Apr 22 09:15:33' (kein Jahr, keine Zeitzone)
>
> Plaso verwendet: '2026-04-22T09:15:33+02:00' (ISO 8601 mit Zeitzone)
>
> Volatility verwendet: Unix-Timestamps: 1745314533
>
> Ohne Normalisierung ist keine Timeline möglich — Events können nicht verglichen werden
>
> ALLE Timestamps werden in UTC umgewandelt: 2026-04-22T07:15:33Z
 
 
 
```
# utils/timestamp.py
from dateutil import parser as dateparser
from datetime import datetime, timezone
 
def to_utc(raw_timestamp: str, system_tz: str = 'UTC') -> datetime:
    '''Konvertiert beliebige Timestamp-Formate nach UTC'''
    try:
        # dateutil erkennt fast alle Formate automatisch
        dt = dateparser.parse(raw_timestamp)
        if dt.tzinfo is None:
            # Keine Zeitzone im Timestamp — System-Zeitzone annehmen
            import pytz
            tz = pytz.timezone(system_tz)
            dt = tz.localize(dt)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)
 
# stages/stage06_normalize.py (v3.1 — DuckDB)
def run(ctx: PipelineContext) -> PipelineContext:
    # Normalisierung per SQL-UPDATE direkt in DuckDB — kein RAM-Peak
    with EventStore(ctx.events_db_path) as store:
        store.normalize_timestamps(lambda ts: to_utc(ts, ctx.timezone).isoformat())
        ctx.normalized_events = store.get_all_sorted()  # einmalig laden
    return ctx
```
 
 
## Stufe 7 — Anti-Forensics-Erkennung
 
 
> **Was ist Anti-Forensics?**
 
>
> Anti-Forensics = Techniken die ein Angreifer nutzt um Spuren zu verwischen
>
> Diese Stufe erkennt ob jemand versucht hat die Untersuchung zu erschweren
>
> Das ist der erste echte Verdachts-Filter der Pipeline
>
> Ergebnisse werden in ctx.antiforensics_hits gespeichert
 
 
 
### Erkannte Anti-Forensics-Techniken:
 
 
| Technik | Erkennungsmethode | Forensische Bedeutung |
| --- | --- | --- |
| Timestomping | $SIA vs $FN Timestamp vergleichen | Dateizeitstempel wurden manipuliert |
| Log-Löschung | Lücken in Log-Sequenznummern | Jemand hat Logs gelöscht |
| Log-Truncation | Log-Datei kleiner als erwartet | Logs wurden abgeschnitten |
| Datei-Verschleierung | Dateiendung passt nicht zum Inhalt | z.B. .txt ist aber EXE |
| Slack Space | Daten in Datei-Slack-Space | Versteckte Daten |
| NTFS ADS | Alternate Data Streams | Versteckte Dateien in NTFS |
| Rootkit-Indikatoren | Prozess im RAM nicht im Dateisystem | Rootkit könnte aktiv sein |
| Secure Delete | Überschriebene freie Blöcke | Bewusste Datenlöschung |
 
 
## Stufe 8 — ML-Anomalieerkennung (Isolation Forest)
 
 
> **Was ist Isolation Forest? (Für Nicht-ML-Entwickler)**
 
>
> Isolation Forest ist ein Machine-Learning-Algorithmus der KEINE Trainingsdaten braucht
>
> Er findet Ereignisse die sich statistisch vom Rest unterscheiden — die 'Ausreißer'
>
> Perfekt für Forensik: Man weiß vorher nicht was 'normal' ist
>
> Jedes Event bekommt einen Anomalie-Score von 0.0 (normal) bis 1.0 (sehr verdächtig)
>
> Events mit Score > 0.7 werden als Anomalien markiert
 
 
 
```
# stages/stage08_ml.py
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import numpy as np
 
def run(ctx: PipelineContext) -> PipelineContext:
    events = ctx.normalized_events
    if len(events) < 10:
        return ctx  # Zu wenig Daten für ML
 
    # Features extrahieren (was der Algorithmus analysiert)
    features = []
    for e in events:
        features.append([
            e.timestamp.hour,              # Uhrzeit (0-23)
            e.timestamp.weekday(),         # Wochentag (0-6)
            len(e.message),                # Länge der Nachricht
            hash(e.source) % 1000,         # Quelle als Zahl
            hash(e.event_type) % 1000,     # Typ als Zahl
            1 if e.user == 'root' else 0,  # Root-Zugriff?
        ])
 
    # Isolation Forest trainieren und anwenden
    clf = IsolationForest(
        contamination=0.01,   # Annahme: 1% der Events sind verdächtig
        random_state=42,      # Für reproduzierbare Ergebnisse
        n_estimators=100,     # Anzahl der Bäume
    )
    X = np.array(features)
    scores = clf.fit_predict(X)  # -1 = Anomalie, 1 = Normal
    raw_scores = clf.decision_function(X)
 
    # Normalisieren: -1..1 → 0..1 (höher = verdächtiger)
    normalized = (raw_scores - raw_scores.min())
    normalized = 1 - (normalized / normalized.max())
 
    for i, event in enumerate(events):
        event.anomaly_score = float(normalized[i])
        if scores[i] == -1:  # Als Anomalie markiert
            ctx.anomalies.append(event)
 
    return ctx
```
 
 
## Stufe 9 — MITRE ATT&CK Mapping
 
 
> **Was ist MITRE ATT&CK?**
 
>
> MITRE ATT&CK ist eine öffentliche Datenbank bekannter Angriffstechniken
>
> Jede Technik hat eine Nummer: z.B. T1053.003 = Cron-basierte Persistenz
>
> Die Pipeline mappt erkannte Ereignisse automatisch auf diese Techniken
>
> Ergebnis: Der Betreuer sieht nicht nur 'verdächtig' sondern welche Angriffstechnik
>
> ATT&CK v15 enthält 600+ Techniken — die Pipeline nutzt die 80 häufigsten
 
 
 
### Beispiel-Mappings (Auswahl):
 
 
| T-Nummer | Technik-Name | Erkennungs-Signal |
| --- | --- | --- |
| T1053.003 | Scheduled Task/Job: Cron | Neuer Crontab-Eintrag + unbekannter User |
| T1070.002 | Clear Linux Logs | Lücken in Log-Sequenz oder leere Log-Datei |
| T1078 | Valid Accounts | Login außerhalb Geschäftszeiten + neue IP |
| T1059.004 | Unix Shell | Unbekannte Shell-Befehle in Bash-History |
| T1105 | Ingress Tool Transfer | Unbekannte IP + Download-Befehl in Logs |
| T1003 | OS Credential Dumping | Zugriff auf /etc/shadow |
| T1098 | Account Manipulation | Neuer User in /etc/passwd |
| T1543.002 | Systemd Service | Neuer unbekannter Systemd-Service |
| T1562.001 | Disable Security Tools | Firewall oder AV deaktiviert |
| T1110 | Brute Force | Viele fehlgeschlagene Logins von einer IP |
 
 
## Stufe 11 — Fehler-Handling & Qualitätsprüfung
 
 
> **Grundregel für alle Stufen**
 
>
> KEINE Stufe darf die gesamte Pipeline zum Absturz bringen
>
> Jede Stufe wird in einem try/except Block ausgeführt
>
> Fehler werden in ctx.stage_errors gespeichert und die Pipeline läuft weiter
>
> Am Ende zeigt Stufe 11 alle Fehler zusammengefasst
 
 
 
```
# pipeline.py — Haupt-Pipeline-Schleife
def run_stage(stage_fn, ctx: PipelineContext, stage_name: str) -> PipelineContext:
    '''Führt eine Stufe aus und fängt alle Fehler ab'''
    try:
        ctx.coc.add_entry(stage_name, 'gestartet')
        result = stage_fn(ctx)
        ctx.stage_status[stage_name] = 'OK'
        ctx.coc.add_entry(stage_name, 'abgeschlossen')
        return result
    except Exception as e:
        ctx.stage_errors[stage_name] = str(e)
        ctx.stage_status[stage_name] = 'FEHLER'
        ctx.coc.add_entry(stage_name, f'FEHLER: {e}')
        log.error(f'Stufe {stage_name} fehlgeschlagen: {e}')
        return ctx  # Weiter mit dem nächsten Schritt
 
# Qualitätsbewertung am Ende
def evaluate_quality(ctx: PipelineContext) -> str:
    error_count = len(ctx.stage_errors)
    if error_count == 0:   return 'SEHR GUT'
    if error_count <= 2:   return 'GUT'
    if error_count <= 5:   return 'EINGESCHRÄNKT'
    return 'KRITISCH'
```
 
 
## Stufe 12 — Export & Archivierung
 
 
> **Was wird erstellt?**
 
>
> report.pdf: Vollständiger Analysebericht für den Betreuer
>
> chain_of_custody.pdf: Rechtliches Beweisprotokoll
>
> timesketch_link.txt: Link zur interaktiven Timeline
>
> pipeline_report.json: Maschinenlesbarer Gesamtreport
>
> autopsy_status.json: Autopsy: lief / übersprungen + Grund
 
 
 
### pipeline_report.json — vollständiges Schema:
 
 
```
{
  'meta': {
    'case_id':        'case_20260422_091533',
    'created':        '2026-04-22T09:15:33Z',
    'pipeline_version': '2.0',
    'duration_minutes': 76
  },
  'input': {
    'disk_image':     '/evidence/disk.E01',
    'ram_dump':       '/evidence/memory.raw',
    'sha256':         'a3f9c2d1...',
    'md5':            'b4e7d1...',
    'size_gb':        50.3,
    'file_type':      'E01'
  },
  'system_profile': {
    'os_family':      'debian',
    'os_name':        'Ubuntu 22.04 LTS',
    'kernel':         '5.15.0-91-generic',
    'hostname':       'webserver-01',
    'timezone':       'Europe/Berlin'
  },
  'statistics': {
    'total_log_lines':    2300000,
    'parsed_events':      847,
    'anomalies_found':    12,
    'iocs_found':         23,
    'mitre_techniques':   5,
    'antiforensics_hits': 3
  },
  'iocs': [
    { 'type': 'ip', 'value': '192.168.1.99', 'confidence': 0.95, 'source': 'auth.log' },
    { 'type': 'domain', 'value': 'evil.example.com', 'confidence': 0.87, 'source': 'dissect' }
  ],
  'mitre_hits': [
    { 'technique': 'T1053.003', 'name': 'Cron', 'tactic': 'Persistence', 'confidence': 0.9 },
    { 'technique': 'T1070.002', 'name': 'Clear Linux Logs', 'tactic': 'Defense Evasion' }
  ],
  'antiforensics': [
    { 'type': 'timestomping', 'file': '/tmp/.hidden', 'details': 'SIA vs FN differ by 3 days' },
    { 'type': 'log_deletion', 'file': '/var/log/auth.log', 'details': 'Sequence gap: 1547-2891' }
  ],
  'stage_status': {
    'stage_01': 'OK',
    'stage_02': 'OK',
    'stage_04_1': 'ÜBERSPRUNGEN — Bedingung 4.1.5',
    'stage_05': 'TSK-FALLBACK — XFS nicht von Dissect lesbar'
  },
  'quality': 'GUT',
  'ioc_quality': 'MITTEL',
  'timesketch_url': 'http://localhost:5000/sketch/1/explore'
}
```
 
 
 
 
 
---
 
# 6. Installation — Schritt für Schritt
 
 
---
 
 
Diese Anleitung ist für Ubuntu 22.04 LTS. Alle Befehle müssen der Reihe nach ausgeführt werden.
 
 
## 6.1 System-Voraussetzungen
 
 
```
# System aktualisieren
sudo apt update && sudo apt upgrade -y
 
# Python 3.11
sudo apt install python3.11 python3.11-venv python3-pip -y
 
# Java (für Autopsy)
sudo apt install default-jre -y
 
# Forensik-Tools
sudo apt install sleuthkit -y       # The Sleuth Kit
sudo apt install wine -y            # Für Zimmerman Tools
sudo apt install xfsprogs -y        # xfs_db für XFS-Dateisysteme
 
# Autopsy installieren
wget https://github.com/sleuthkit/autopsy/releases/latest
sudo dpkg -i autopsy_*.deb
 
# Docker (für Timesketch)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```
 
 
## 6.2 Python-Abhängigkeiten
 
 
```
# Virtuelle Umgebung erstellen
python3.11 -m venv venv
source venv/bin/activate
 
# requirements.txt — alle Pakete mit exakten Versionen
pip install dissect==5.0.0
pip install volatility3==2.5.0
pip install timesketch-api-client==20240101
pip install scikit-learn==1.4.0
pip install pandas==2.2.0
pip install python-magic==0.4.27
pip install reportlab==4.1.0
pip install attackcti==0.3.4
pip install yara-python==4.3.1
pip install python-dateutil==2.9.0
pip install pytz==2024.1
pip install numpy==1.26.4
pip install duckdb  # Event-Store (RAM-Entlastung)
```
 
 
## 6.3 Timesketch starten (Docker)
 
 
```
# docker-compose.yml herunterladen
curl -O https://raw.githubusercontent.com/google/timesketch/main/docker-compose.yml
 
# Timesketch starten
docker-compose up -d
 
# Warten bis Timesketch bereit ist (ca. 2-3 Minuten)
docker-compose logs -f timesketch
 
# Browser öffnen
# http://localhost:5000
# Standard-Login: admin / changeme
```
 
 
## 6.4 Konfiguration (config.yaml)
 
 
```
# config.yaml
timesketch:
  host:       'http://localhost:5000'
  username:   'admin'
  password:   'changeme'   # ÄNDERN!
  sketch_id:  1
 
autopsy:
  binary:     '/usr/bin/autopsy'
  java_home:  '/usr/lib/jvm/default-java'
 
ml:
  contamination: 0.01     # 1% Anomalie-Rate angenommen
  anomaly_threshold: 0.7  # Ab diesem Score = Anomalie
 
logging:
  level:      'INFO'      # DEBUG, INFO, WARNING, ERROR
  file:       'pipeline.log'
```
 
 
 
 
 
---
 
# 7. Report & PDF Design — Strukturvorlage
 
 
---
 
 
Dieses Kapitel beschreibt exakt wie die report.pdf und die chain_of_custody.pdf aussehen müssen. Als Referenz liegt dem Pflichtenheft ein separates Beispiel-PDF (DFIR_Report_Beispiel.pdf) bei — dieses zeigt das finale Design Seite für Seite.
 
 
> **Design-System**
 
>
> Sprache: Deutsch
>
> Stil: Professionell / Corporate
>
> Primärfarbe: #1F4E79 (Dunkelblau)
>
> Sekundärfarbe: #2E75B6 (Mittelblau)
>
> Akzentfarbe: #D5E8F0 (Hellblau)
>
> Schrift: Helvetica (Standard) / Helvetica-Bold (Überschriften) / Courier (Code)
>
> Seitenformat: A4 (210 x 297 mm)
>
> Margins: Links/Rechts 15mm, Oben 35mm (Header), Unten 22mm (Footer)
>
> Library: reportlab (Python) — pip install reportlab
 
 
 
## 7.1 Header & Footer — auf jeder Seite
 
 
> **Header (oben, 28mm hoch)**
 
>
> Hintergrund: #1F4E79 (Dunkelblau)
>
> Links: 'DFIR ANALYSE-REPORT' in Weiß, Helvetica-Bold 13pt
>
> Darunter: 'Case-ID: ... | Erstellt: ... | VERTRAULICH' in Hellblau 8pt
>
> Rechts: Status-Badge 'ANALYSE ABGESCHLOSSEN' in Grün mit Qualitäts-Info
 
 
 
> **Footer (unten, 15mm hoch)**
 
>
> Trennlinie: 0.5pt in #F2F2F2 (Hellgrau)
>
> Links: 'DFIR Analyse-Pipeline v2.0 | Automatisch generiert | Nicht für die Öffentlichkeit'
>
> Rechts: 'Seite X von Y'
>
> Schrift: Helvetica 7pt in #595959 (Grau)
 
 
 
## 7.2 report.pdf — Aufbau Seite für Seite
 
 
### Seite 1 — Deckblatt & Case-Informationen
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Deckblatt-Banner | DFIR ANALYSE-REPORT | Dunkelblau #1F4E79, Weiß, 28pt Bold, volle Breite |
| Untertitel | Automatisch generierter forensischer Analysebericht | Blau #2E75B6, 11pt |
| Case-Informationen | Case-ID, Datum, Dauer, Image, SHA256, MD5, Qualität | Key-Value Tabelle, grauer Key, weißer Value |
| System-Info | OS, Kernel, Hostname, Zeitzone, Autopsy-Status, TSK-Status | Key-Value Tabelle |
 
 
### Seite 2 — Executive Summary
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Statistik-Boxen (5x) | Log-Zeilen, Events, Anomalien, IOCs, MITRE-Techniken | Grauer Hintergrund, farbige Zahl (22pt), Unterschrift (8pt) |
| Kritische Funde | Tabelle: Schwere, Zeitstempel, Beschreibung, MITRE | Rot für KRITISCH, Orange für HOCH, Gelb für MITTEL |
| Empfehlung-Box | Sofortmaßnahmen nummeriert | Roter linker Rand, roter Hintergrund |
 
 
### Seite 3 — MITRE ATT&CK Mapping
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Einleitung | Erklärung was MITRE ATT&CK ist | Body-Text 9pt |
| MITRE-Tabelle | T-Nummer, Technik, Taktik-Phase, Confidence, Quelle | Dunkelblauer Header, Zebra-Zeilen |
| Kill-Chain | 6 Phasen horizontal: Reconnaissance bis Credential Access | ROT = erkannte Phase, GRAU = nicht erkannt |
 
 
### Seite 4 — IOC-Liste
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| IOC-Qualität-Box | HOCH oder MITTEL + Begründung | Grüner Rand (HOCH) oder Oranger Rand (MITTEL) |
| IP-Adressen | Tabelle: IP, Typ, Confidence, Quelle, Timestamp | Dunkelblauer Header, Zebra-Zeilen |
| Domains / URLs | Tabelle: Domain, Confidence, Quelle, Timestamp | Dunkelblauer Header, Zebra-Zeilen |
| Datei-Hashes | Tabelle: Hash (MD5), Datei, Status, Quelle | Dunkelblauer Header, Zebra-Zeilen |
 
 
### Seite 5 — Anti-Forensics & ML-Anomalien
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Warn-Box | Anzahl erkannte Techniken + Warnung | Roter Rand, roter Hintergrund |
| Anti-Forensics-Tab | Technik, Betroffene Datei, Details, Schwere | Dunkelblauer Header, Zebra-Zeilen |
| ML-Erklärung | Kurze Erklärung Isolation Forest | Body-Text 9pt |
| Anomalien-Tabelle | Score, Zeitstempel, Event, Quelle | Dunkelblauer Header, Zebra-Zeilen |
 
 
### Seite 6 — Forensische Timeline
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Einleitung | Hinweis dass alle Timestamps UTC sind | Body-Text 9pt |
| Timeline-Tabelle | Zeitstempel, Ereignis, Quelle, Schwere (farbig) | Dunkelblauer Header, Zeilen farbig nach Schwere |
| Timesketch-Box | Link zu http://localhost:5000/... | Blauer Rand, blauer Hintergrund |
 
 
### Seite 7 — System-Profiling & Pipeline-Status
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| System-Profiling | OS, Kernel, Hostname, Zeitzone, Ports, Benutzer | Key-Value Tabelle |
| Pipeline-Status | Alle 15 Stufen mit Status, Dauer, Anmerkung | OK=normal, ÜBERSPRUNGEN=Grau, FEHLER=Rot |
 
 
### Seite 8 — Chain of Custody
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Integritäts-Box | SHA256 vorher = SHA256 nachher → BESTANDEN | Grüner Rand, grüner Hintergrund |
| Beweisdaten | Dateiname, SHA256, MD5, Größe, Empfangsdatum | Key-Value Tabelle |
| Ausführungsprotokoll | Alle Stufen mit Aktion, Timestamp, Status | Dunkelblauer Header, Zebra-Zeilen |
| Abschluss | Rechtlicher Hinweis + Timesketch-Link | Trennlinie + Body-Text |
 
 
### Seite 9 — Parser-Statistik (NEU)
 
 
Diese Seite ist neu dazugekommen durch die vollständige Parser-Implementierung. Der Betreuer sieht sofort welche der 38 Parser aktiv waren und welche Log-Formate im Image nicht vorhanden waren.
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| Einleitung | Erklärung was die Tabelle zeigt | Body-Text 9pt |
| Parser-Tabelle | Parser-Name, Log-Datei, Event-Anzahl, Status (Aktiv/Nicht vorhanden/Fallback) | Dunkelblauer Header, Zebra-Zeilen, 0-Events in Grau |
| Zusammenfassung | Aktive Parser / Nicht vorhanden / Events gesamt / Fallback genutzt | 4 große Zahlen mit Farben: Grün/Grau/Blau/Orange |
 
 
> **Wichtig für Entwickler — Farb-Logik in Parser-Tabelle**
 
>
> Zeilen mit Events = 0 → Hintergrund: #F2F2F2 (Hellgrau) — Status: 'Nicht vorhanden'
>
> Zeilen mit Plaso Fallback → Hintergrund: #FFEB9C (Gelb) — Status: 'Fallback aktiv'
>
> Zeilen mit Events > 0 → Normal (Zebra) — Status: 'Aktiv'
>
> Binäre Parser → Status: 'Aktiv (Binär)'
 
 
 
### Seite 10 — YARA-Treffer & Erweiterte IOCs (NEU)
 
 
Diese Seite ist neu durch die YARA-Integration. Sie zeigt welche YARA-Regeln angeschlagen haben und eine erweiterte IOC-Liste mit Parser-Herkunft.
 
 
| Element | Inhalt | Design |
| --- | --- | --- |
| YARA-Treffer-Tabelle | YARA-Regel, Regel-Quelle (Custom/Community/Signature-Base), Betroffene Datei, Schwere | Dunkelblauer Header, Zeilen farbig nach Schwere |
| Erweiterte IOC-Tabelle | IOC-Typ, Wert, Confidence, Parser, Log-Datei, Timestamp | Dunkelblauer Header, Zebra-Zeilen — 6 Spalten statt vorher 4 |
| IOC-Qualität-Box | Zusammenfassung: X IOCs aus Y Parsern, YARA-Bonus-IOCs | Grüner Rand (HOCH) oder Oranger Rand (MITTEL) |
 
 
 
 
## 7.3 Design-Elemente — Implementierungsreferenz
 
 
### Farben (HEX)
 
 
| Name | HEX-Wert | Verwendung |
| --- | --- | --- |
| Dunkelblau | #1F4E79 | Header-Hintergrund, Tabellen-Header, Überschriften H1 |
| Mittelblau | #2E75B6 | Überschriften H2, Trennlinien, Links |
| Hellblau | #D5E8F0 | Abschnitts-Banner, Key-Spalte in KV-Tabellen |
| Dunkelgrau | #404040 | Body-Text, Tabellen-Inhalt |
| Mittelgrau | #595959 | Footer, Labels, Sekundär-Text |
| Hellgrau | #F2F2F2 | Zebra-Zeilen, Statistik-Box Hintergrund |
| Grün | #375623 | Status OK, IOC-Qualität HOCH |
| Grün-Hell | #E2EFDA | OK-Box Hintergrund |
| Orange | #843C0C | Severity HOCH, Warnungen |
| Orange-Hell | #FCE4D6 | HOCH-Zeilen Hintergrund |
| Rot | #C00000 | Severity KRITISCH, Anti-Forensics |
| Rot-Hell | #FFCCCC | KRITISCH-Zeilen Hintergrund |
| Gelb-Hell | #FFEB9C | Severity MITTEL Hintergrund |
| Code-BG | #1A1A2E | Code-Block Hintergrund |
| Code-Text | #C8D3F5 | Code-Block Schriftfarbe |
 
 
### Schriftgrößen
 
 
| Element | Font | Größe |
| --- | --- | --- |
| Header Titel | Helvetica-Bold | 13pt |
| Header Untertitel | Helvetica | 8pt |
| H1 Abschnitts-Titel | Helvetica-Bold | 14pt — Farbe #1F4E79 |
| H2 Unter-Abschnitt | Helvetica-Bold | 11pt — Farbe #2E75B6 |
| H3 Detail-Überschrift | Helvetica-Bold | 10pt — Farbe #404040 |
| Body-Text | Helvetica | 9pt |
| Tabellen-Header | Helvetica-Bold | 8pt — Weiß auf Dunkelblau |
| Tabellen-Inhalt | Helvetica | 8pt |
| Statistik-Wert | Helvetica-Bold | 22pt — farbig |
| Statistik-Label | Helvetica-Bold | 8pt — Grau |
| Code | Courier | 8pt — Hellblau auf Dunkel |
| Footer | Helvetica | 7pt — Grau |
 
 
### Tabellen-Design — Standardregeln
 
 
> **Für alle Tabellen im Report gilt**
 
>
> Header-Zeile: Hintergrund #1F4E79 (Dunkelblau), Text Weiß, Helvetica-Bold 8pt
>
> Zebra-Zeilen: Ungerade Zeilen Weiß, Gerade Zeilen #F2F2F2 (Hellgrau)
>
> Padding: Links/Rechts 5pt, Oben/Unten 4pt
>
> Trennlinien: 0.3pt in #DDDDDD zwischen Zeilen
>
> Kritische Zeilen: Hintergrund #FFCCCC (Rot-Hell)
>
> Hohe Zeilen: Hintergrund #FCE4D6 (Orange-Hell)
>
> Mittlere Zeilen: Hintergrund #FFEB9C (Gelb-Hell)
>
> Key-Value Tabellen: Key-Spalte #F2F2F2, Value-Spalte Weiß
 
 
 
 
 
 
---
 
# 8. Fehlerbehandlung — Vollständige Referenz
 
 
---
 
 
| Fehler | Ursache | Lösung |
| --- | --- | --- |
| Dissect gibt leeres Ergebnis | XFS, Btrfs oder korruptes Image | TSK Fallback wird automatisch aktiviert |
| Autopsy startet nicht | Java nicht installiert | apt install default-jre |
| Volatility findet keine Symbole | OS-Version nicht in Symbol-DB | Symbols manuell herunterladen |
| Timesketch nicht erreichbar | Docker nicht gestartet | docker-compose up -d |
| python-magic Fehler | libmagic nicht installiert | apt install libmagic1 |
| Hash-Verifizierung schlägt fehl | Image wurde verändert | KRITISCH: Im Report vermerken |
| Hayabusa findet kein EVTX | Kein Windows-System im Image | Stufe wird übersprungen — kein Fehler |
| Isolation Forest Memory Error | Zu viele Events (> 5 Mio) | Sampling: nur 500k Events verwenden |
| MITRE-API nicht erreichbar | Kein Internet oder API down | Lokale ATT&CK-JSON-Datei verwenden |
| Reportlab PDF-Fehler | Sonderzeichen im Bericht | UTF-8 encoding erzwingen |
 
 
 
 
 
---
 
# 9. Mehrwert — Was der Betreuer gewinnt
 
---
 
| Ohne Pipeline | Mit Pipeline |
| --- | --- |
| Manuelles Mounten: ~30 Min | Kein Mounten nötig — direkt lesen |
| Tool-Auswahl und Setup: ~2 Std | Einen Befehl eingeben: ~1 Min |
| 2,3 Mio Log-Zeilen durchsuchen: ~8 Std | 847 gefilterte Events im Report: ~1 Std |
| MITRE-Mapping manuell: ~3 Std | Automatisch in Stufe 9: 0 Min |
| Chain of Custody manuell: ~1 Std | Automatisch generiert: 0 Min |
| **GESAMT: 1-2 Arbeitstage** | **GESAMT: 2-4 Stunden** |
 
→ Vollständige Parser-Implementierung siehe Kapitel 10-14
 
---
 
# 10. Vollständige Parser-Implementierung
 
 
---
 
 
Dieses Kapitel beschreibt alle 38 Log-Parser vollständig und mit exakter Implementierungs-Logik. Jeder Parser erbt von BaseParser und gibt eine Liste von ForensicEvent-Objekten zurück. Claude Code kann diese Spezifikationen direkt in Python umsetzen.
 
 
> **Basis-Klasse — gilt für ALLE Parser**
 
>
> Datei: parsers/base_parser.py
>
> Alle Parser erben von BaseParser
>
> Methode can_parse(path) → bool: Prüft ob Parser die Datei lesen kann
>
> Methode parse(path) → List[ForensicEvent]: Liest Datei und gibt Events zurück
>
> Timestamps IMMER mit to_utc() in UTC umwandeln
>
> Bei Fehler: leere Liste zurückgeben, Fehler loggen — KEIN Exception-Crash
 
 
 
```
# parsers/base_parser.py — VOLLSTÄNDIGE IMPLEMENTIERUNG
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timezone
from models.event import ForensicEvent
import logging
import re
 
log = logging.getLogger(__name__)
 
class BaseParser(ABC):
    name: str = ''
    file_patterns: List[str] = []  # z.B. ['syslog', 'syslog.*']
    binary: bool = False           # True = Binärdatei (wtmp, utmp, lastlog)
 
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        pass
 
    @abstractmethod
    def parse(self, file_path: Path) -> List[ForensicEvent]:
        pass
 
    def safe_parse(self, file_path: Path) -> List[ForensicEvent]:
        '''Wrapper mit Fehlerbehandlung — immer diese Methode aufrufen'''
        try:
            return self.parse(file_path)
        except Exception as e:
            log.warning(f'Parser {self.name} fehlgeschlagen für {file_path}: {e}')
            return []
 
    def make_event(self, timestamp, source, event_type, message,
                   user=None, ip=None, process=None,
                   file_path=None, severity='info', raw=None) -> ForensicEvent:
        from utils.timestamp import to_utc
        return ForensicEvent(
            timestamp  = to_utc(str(timestamp)) if not isinstance(timestamp, datetime) else timestamp,
            source     = source,
            event_type = event_type,
            message    = message,
            user       = user,
            ip         = ip,
            process    = process,
            file_path  = str(file_path) if file_path else None,
            severity   = severity,
            raw        = raw or {},
        )
 
    def read_lines(self, path: Path) -> List[str]:
        '''Liest Textdatei mit Encoding-Fallback'''
        for enc in ['utf-8', 'latin-1', 'cp1252']:
            try:
                return path.read_text(encoding=enc).splitlines()
            except (UnicodeDecodeError, PermissionError):
                continue
        return []
```
 
 
 
 
## 10.1 Linux System-Logs (8 Parser)
 
 
### Parser 1 — SyslogParser
 
 
> **Datei-Pfade**
 
>
> Debian/Ubuntu: /var/log/syslog, /var/log/syslog.1, /var/log/syslog.2.gz
>
> RHEL/CentOS:   /var/log/messages, /var/log/messages-*
>
> Alpine:        /var/log/messages
 
 
 
```
# parsers/syslog_parser.py
import gzip, re
from pathlib import Path
 
# Syslog Format: 'Apr 22 09:15:33 hostname process[pid]: message'
PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.+)$'
)
 
class SyslogParser(BaseParser):
    name = 'syslog'
    file_patterns = ['syslog', 'syslog.*', 'messages', 'messages-*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('syslog', 'messages'))
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        lines = self._read(path)  # Liest auch .gz Dateien
        current_year = datetime.now().year  # Syslog hat kein Jahr
        for line in lines:
            m = PATTERN.match(line)
            if not m: continue
            # Timestamp zusammensetzen (Jahr fehlt im Syslog!)
            raw_ts = f'{current_year} {m["month"]} {m["day"]} {m["time"]}'
            severity = self._detect_severity(m['msg'])
            events.append(self.make_event(
                timestamp  = raw_ts,
                source     = 'syslog',
                event_type = 'system',
                message    = m['msg'],
                process    = m['process'],
                severity   = severity,
                raw        = m.groupdict(),
            ))
        return events
 
    def _read(self, path: Path) -> List[str]:
        if path.suffix == '.gz':
            with gzip.open(path, 'rt', errors='replace') as f:
                return f.read().splitlines()
        return self.read_lines(path)
 
    def _detect_severity(self, msg: str) -> str:
        msg_lower = msg.lower()
        if any(w in msg_lower for w in ['error','fail','critical','emerg','alert']):
            return 'high'
        if any(w in msg_lower for w in ['warn','warning']):
            return 'medium'
        return 'info'
```
 
 
### Parser 2 — AuthLogParser
 
 
> **Datei-Pfade**
 
>
> Debian/Ubuntu: /var/log/auth.log, /var/log/auth.log.*
>
> RHEL/CentOS:   /var/log/secure, /var/log/secure-*
 
 
 
```
# parsers/auth_parser.py
# Erkennt: SSH-Logins, sudo, su, PAM, useradd, passwd
 
SSH_SUCCESS = re.compile(r'Accepted (password|publickey) for (\S+) from ([\d.]+)')
SSH_FAIL    = re.compile(r'Failed (password|publickey) for (\S+) from ([\d.]+)')
SSH_INVALID = re.compile(r'Invalid user (\S+) from ([\d.]+)')
SUDO_CMD    = re.compile(r'(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.+)')
NEW_USER    = re.compile(r'new user: name=(\S+)')
USER_DEL    = re.compile(r'delete user (.+)')
 
class AuthLogParser(BaseParser):
    name = 'auth'
    file_patterns = ['auth.log', 'auth.log.*', 'secure', 'secure-*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('auth.log', 'secure'))
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m_base = PATTERN.match(line)  # Syslog-Basis-Pattern
            if not m_base: continue
            msg = m_base['msg']
            ts  = f'{datetime.now().year} {m_base["month"]} {m_base["day"]} {m_base["time"]}'
 
            # SSH Login erfolgreich
            m = SSH_SUCCESS.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'ssh_login_success',
                    f'SSH Login erfolgreich: User={m[2]} IP={m[3]} Methode={m[1]}',
                    user=m[2], ip=m[3], severity='medium'))
                continue
 
            # SSH Login fehlgeschlagen
            m = SSH_FAIL.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'ssh_login_failed',
                    f'SSH Login fehlgeschlagen: User={m[2]} IP={m[3]}',
                    user=m[2], ip=m[3], severity='high'))
                continue
 
            # Ungültiger User
            m = SSH_INVALID.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'ssh_invalid_user',
                    f'Ungültiger SSH-User: {m[1]} von {m[2]}',
                    user=m[1], ip=m[2], severity='high'))
                continue
 
            # Sudo-Befehl
            m = SUDO_CMD.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'sudo_command',
                    f'Sudo: {m[1]} führte als {m[2]} aus: {m[3]}',
                    user=m[1], process='sudo', severity='medium'))
                continue
 
            # Neuer User
            m = NEW_USER.search(msg)
            if m:
                events.append(self.make_event(ts, 'auth', 'user_created',
                    f'Neuer Benutzer erstellt: {m[1]}',
                    user=m[1], severity='high'))
        return events
```
 
 
### Parser 3 — JournaldParser
 
 
> **Datei-Pfade & Besonderheit**
 
>
> Pfad: /var/log/journal/**/*.journal (binäres Format)
>
> Benötigt: systemd-python Paket (pip install systemd-python)
>
> Fallback: journalctl-Ausgabe als Text parsen falls systemd-python fehlt
>
> Enthält: alle System-Events inkl. Kernel, Services, Auth
 
 
 
```
# parsers/journald_parser.py
from pathlib import Path
import subprocess, json
 
class JournaldParser(BaseParser):
    name = 'journald'
    file_patterns = ['*.journal']
    binary = True
 
    def can_parse(self, path: Path) -> bool:
        return path.suffix == '.journal'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        # Methode 1: journalctl (bevorzugt)
        try:
            result = subprocess.run([
                'journalctl', '--file', str(path),
                '--output=json', '--no-pager'
            ], capture_output=True, text=True, timeout=120)
            for line in result.stdout.splitlines():
                try:
                    entry = json.loads(line)
                    ts_us = int(entry.get('__REALTIME_TIMESTAMP', 0))
                    ts    = datetime.fromtimestamp(ts_us / 1e6, tz=timezone.utc)
                    msg   = entry.get('MESSAGE', '')
                    unit  = entry.get('_SYSTEMD_UNIT', '')
                    prio  = int(entry.get('PRIORITY', 6))
                    severity = {0:'critical',1:'critical',2:'critical',
                                3:'high',4:'medium',5:'medium',
                                6:'info',7:'info'}.get(prio, 'info')
                    events.append(self.make_event(
                        timestamp=ts, source='journald',
                        event_type='system', message=str(msg),
                        process=unit, severity=severity, raw=entry
                    ))
                except (json.JSONDecodeError, ValueError):
                    continue
        except FileNotFoundError:
            pass  # journalctl nicht verfügbar
        return events
```
 
 
### Parser 4 — KernLogParser
 
 
```
# parsers/kern_parser.py
# Format: 'Apr 22 09:15:33 hostname kernel: [12345.678] message'
KERN_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+\S+\s+kernel:\s+(?:\[\s*[\d.]+\]\s*)?(?P<msg>.+)$'
)
# Kritische Kernel-Keywords die als HIGH markiert werden:
KERN_CRITICAL = ['oom','killed process','out of memory','panic','call trace',
                 'segfault','oops','bug:','hardware error','mce:']
 
class KernLogParser(BaseParser):
    name = 'kern'
    file_patterns = ['kern.log', 'kern.log.*', 'dmesg']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('kern.log', 'dmesg'))
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = KERN_PATTERN.match(line)
            if not m: continue
            msg = m['msg']
            sev = 'high' if any(k in msg.lower() for k in KERN_CRITICAL) else 'info'
            events.append(self.make_event(
                f'{datetime.now().year} {m["month"]} {m["day"]} {m["time"]}',
                'kernel', 'kernel_event', msg, severity=sev
            ))
        return events
```
 
 
### Parser 5 — BootLogParser
 
 
```
# parsers/boot_parser.py
# Pfad: /var/log/boot.log
# Format: Zeitstempel + Status [OK]/[FAILED]/[WARNING]
BOOT_PATTERN = re.compile(r'\[\s*(?P<status>OK|FAILED|WARNING)\s*\]\s*(?P<msg>.+)')
 
class BootLogParser(BaseParser):
    name = 'boot'
    file_patterns = ['boot.log', 'boot.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('boot.log')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        boot_time = datetime.now(tz=timezone.utc)  # Annäherung
        for line in self.read_lines(path):
            m = BOOT_PATTERN.search(line)
            if not m: continue
            status = m['status']
            sev = 'high' if status == 'FAILED' else 'medium' if status == 'WARNING' else 'info'
            events.append(self.make_event(
                boot_time, 'boot', f'boot_{status.lower()}',
                f'Boot: [{status}] {m["msg"]}', severity=sev
            ))
        return events
```
 
 
### Parser 6 — DaemonLogParser
 
 
```
# parsers/daemon_parser.py
# Pfad: /var/log/daemon.log
# Format: identisch mit Syslog
# Enthält: Daemon-Start/Stop, Netzwerk-Events, Systemd-Service-Events
 
class DaemonLogParser(SyslogParser):  # Erbt von SyslogParser
    name = 'daemon'
    file_patterns = ['daemon.log', 'daemon.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('daemon.log')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = super().parse(path)  # Syslog-Parser nutzen
        for e in events:
            e.source = 'daemon'  # Source überschreiben
            e.event_type = 'daemon_event'
        return events
```
 
 
### Parser 7 — WtmpParser (Binär)
 
 
> **Wichtig — Binärformat**
 
>
> wtmp ist eine BINÄRE Datei — kann nicht als Text gelesen werden
>
> Enthält: Login/Logout-History, Reboot-Zeitstempel, Runlevel-Änderungen
>
> Python-Struct: '<hh32s4s4shhiii4i20s' (utmp struct laut Linux man page)
>
> Pfad: /var/log/wtmp
 
 
 
```
# parsers/wtmp_parser.py
import struct
from datetime import datetime, timezone
 
# Linux utmp struct (384 Bytes pro Eintrag)
UTMP_STRUCT = '<hh32s4s4shhiii4i20s'
UTMP_SIZE   = struct.calcsize(UTMP_STRUCT)
 
UT_TYPES = {
    0: 'empty', 1: 'run_level', 2: 'boot_time',
    3: 'new_time', 4: 'old_time', 5: 'init_process',
    6: 'login_process', 7: 'user_process', 8: 'dead_process',
}
 
class WtmpParser(BaseParser):
    name = 'wtmp'
    file_patterns = ['wtmp', 'wtmp.*']
    binary = True
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('wtmp')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        try:
            data = path.read_bytes()
        except PermissionError:
            return []
        offset = 0
        while offset + UTMP_SIZE <= len(data):
            chunk = data[offset:offset + UTMP_SIZE]
            offset += UTMP_SIZE
            try:
                fields = struct.unpack(UTMP_STRUCT, chunk)
            except struct.error:
                continue
            ut_type = fields[0]
            ut_user = fields[4].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_host = fields[3].rstrip(b'\x00').decode('utf-8', errors='replace')
            ut_tv_sec = fields[9]
            if ut_tv_sec == 0: continue
            ts = datetime.fromtimestamp(ut_tv_sec, tz=timezone.utc)
            type_name = UT_TYPES.get(ut_type, 'unknown')
            if type_name in ('user_process', 'dead_process', 'boot_time'):
                sev = 'medium' if type_name == 'user_process' else 'info'
                events.append(self.make_event(
                    ts, 'wtmp', type_name,
                    f'{type_name}: User={ut_user} Host={ut_host}',
                    user=ut_user, severity=sev
                ))
        return events
```
 
 
### Parser 8 — LastlogParser (Binär)
 
 
```
# parsers/lastlog_parser.py
# Pfad: /var/log/lastlog (Binär, fester Index nach UID)
# Enthält: Letzter Login-Timestamp pro User
import struct, pwd
 
LASTLOG_STRUCT = '<l32s256s'  # time, line, host
LASTLOG_SIZE   = struct.calcsize(LASTLOG_STRUCT)
 
class LastlogParser(BaseParser):
    name = 'lastlog'
    file_patterns = ['lastlog']
    binary = True
 
    def can_parse(self, path: Path) -> bool:
        return path.name == 'lastlog'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        data = path.read_bytes()
        uid = 0
        offset = 0
        while offset + LASTLOG_SIZE <= len(data):
            chunk = data[offset:offset+LASTLOG_SIZE]
            offset += LASTLOG_SIZE
            ts_sec, line, host = struct.unpack(LASTLOG_STRUCT, chunk)
            if ts_sec > 0:
                ts   = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
                host = host.rstrip(b'\x00').decode('utf-8', errors='replace')
                events.append(self.make_event(
                    ts, 'lastlog', 'last_login',
                    f'Letzter Login UID={uid} von {host}',
                    severity='info'
                ))
            uid += 1
        return events
```
 
 
 
 
## 10.2 Paket-Manager-Logs (5 Parser)
 
 
### Parser 9 — DpkgParser (Debian/Ubuntu)
 
 
```
# parsers/dpkg_parser.py
# Pfad: /var/log/dpkg.log
# Format: '2026-04-22 09:15:33 install/upgrade/remove package version'
DPKG_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(?P<action>\S+)\s+(?P<pkg>\S+)\s+(?P<ver>.+)$'
)
DPKG_SUSPICIOUS = ['netcat','nmap','hydra','john','hashcat',
                   'aircrack','metasploit','sqlmap','nikto']
 
class DpkgParser(BaseParser):
    name = 'dpkg'
    file_patterns = ['dpkg.log', 'dpkg.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('dpkg.log')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = DPKG_PATTERN.match(line)
            if not m: continue
            pkg = m['pkg']
            # Verdächtige Tools erkennen
            sev = 'high' if any(s in pkg.lower() for s in DPKG_SUSPICIOUS) else 'info'
            events.append(self.make_event(
                m['ts'], 'dpkg', f'pkg_{m["action"]}',
                f'Paket {m["action"]}: {pkg} Version={m["ver"]}',
                severity=sev, raw={'action': m['action'], 'package': pkg}
            ))
        return events
```
 
 
### Parser 10 — AptHistoryParser
 
 
```
# parsers/apt_parser.py
# Pfad: /var/log/apt/history.log
# Format: Mehrzeilige Einträge mit Start-Date, Commandline, Install, Remove
class AptHistoryParser(BaseParser):
    name = 'apt'
    file_patterns = ['history.log', 'history.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('history.log')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        content = path.read_text(errors='replace')
        # Einträge durch Leerzeilen getrennt
        for block in content.split('
 
'):
            ts_m  = re.search(r'Start-Date: (.+)', block)
            cmd_m = re.search(r'Commandline: (.+)', block)
            if not ts_m: continue
            ts  = ts_m.group(1).strip()
            cmd = cmd_m.group(1).strip() if cmd_m else ''
            events.append(self.make_event(
                ts, 'apt', 'apt_operation',
                f'APT Befehl: {cmd}',
                process='apt', severity='info'
            ))
        return events
```
 
 
### Parser 11 — YumParser (RHEL/CentOS)
 
 
```
# parsers/yum_parser.py
# Pfad: /var/log/yum.log
# Format: 'Apr 22 09:15:33 Installed: package-version'
YUM_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+(?P<action>\S+):\s+(?P<pkg>.+)$'
)
 
class YumParser(BaseParser):
    name = 'yum'
    file_patterns = ['yum.log', 'yum.log-*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('yum.log')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = YUM_PATTERN.match(line)
            if not m: continue
            events.append(self.make_event(
                f'{datetime.now().year} {m["month"]} {m["day"]} {m["time"]}',
                'yum', f'pkg_{m["action"].lower()}',
                f'YUM {m["action"]}: {m["pkg"]}',
                severity='info'
            ))
        return events
```
 
 
### Parser 12 — DnfParser (Fedora/RHEL8+)
 
 
```
# parsers/dnf_parser.py
# Pfad: /var/log/dnf.log, /var/log/dnf.rpm.log
# Format: '2026-04-22T09:15:33+0200 INFO action'
DNF_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})'
    r'\s+(?P<level>\w+)\s+(?P<msg>.+)$'
)
 
class DnfParser(BaseParser):
    name = 'dnf'
    file_patterns = ['dnf.log', 'dnf.rpm.log']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('dnf')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = DNF_PATTERN.match(line)
            if not m: continue
            events.append(self.make_event(
                m['ts'], 'dnf', 'pkg_operation', m['msg'], severity='info'
            ))
        return events
```
 
 
### Parser 13 — PacmanParser (Arch Linux)
 
 
```
# parsers/pacman_parser.py
# Pfad: /var/log/pacman.log
# Format: '[2026-04-22T09:15:33+0100] [PACMAN] action'
PACMAN_PATTERN = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+\[(?P<actor>\w+)\]\s+(?P<msg>.+)$'
)
 
class PacmanParser(BaseParser):
    name = 'pacman'
    file_patterns = ['pacman.log']
 
    def can_parse(self, path: Path) -> bool:
        return path.name == 'pacman.log'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = PACMAN_PATTERN.match(line)
            if not m: continue
            events.append(self.make_event(
                m['ts'], 'pacman', 'pkg_operation', m['msg'], severity='info'
            ))
        return events
```
 
 
 
 
## 10.3 Web-Server-Logs (4 Parser)
 
 
### Parser 14 — ApacheAccessParser
 
 
> **Datei-Pfade**
 
>
> Ubuntu/Debian: /var/log/apache2/access.log, /var/log/apache2/other_vhosts_access.log
>
> RHEL/CentOS:   /var/log/httpd/access_log
>
> Format:        Combined Log Format (CLF)
 
 
 
```
# parsers/apache_access_parser.py
# Format: '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326'
APACHE_CLF = re.compile(
    r'^(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?$'
)
SUSPICIOUS_PATHS = ['/etc/passwd','/etc/shadow','../','..%2f',
                    'wp-admin','phpmyadmin','/.env','/.git',
                    '/shell','/cmd','exec(','union select']
 
class ApacheAccessParser(BaseParser):
    name = 'apache_access'
    file_patterns = ['access.log', 'access_log', 'other_vhosts_access.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'access' in path.name and path.suffix in ('', '.log', '.1')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = APACHE_CLF.match(line)
            if not m: continue
            status = int(m['status'])
            path_req = m['path']
            # Severity bestimmen
            if status >= 500: sev = 'high'
            elif status >= 400: sev = 'medium'
            elif any(s in path_req.lower() for s in SUSPICIOUS_PATHS): sev = 'high'
            else: sev = 'info'
            events.append(self.make_event(
                m['ts'], 'apache_access', 'http_request',
                f'{m["method"]} {path_req} → {status}',
                ip=m['ip'], severity=sev,
                raw={'method':m['method'],'path':path_req,'status':status}
            ))
        return events
```
 
 
### Parser 15 — ApacheErrorParser
 
 
```
# parsers/apache_error_parser.py
# Format: '[Fri Apr 22 09:15:33.123456 2026] [module:level] [pid N] message'
APACHE_ERR = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+\[(?P<module>[^:]+):(?P<level>\w+)\]'
    r'\s+\[pid\s+(?P<pid>\d+)\]\s+(?P<msg>.+)$'
)
 
class ApacheErrorParser(BaseParser):
    name = 'apache_error'
    file_patterns = ['error.log', 'error_log']
 
    def can_parse(self, path: Path) -> bool:
        return 'error' in path.name
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {'emerg':'critical','alert':'critical','crit':'high',
                     'error':'high','warn':'medium','notice':'info','info':'info'}
        for line in self.read_lines(path):
            m = APACHE_ERR.match(line)
            if not m: continue
            sev = LEVEL_MAP.get(m['level'].lower(), 'info')
            events.append(self.make_event(
                m['ts'], 'apache_error', 'http_error', m['msg'], severity=sev
            ))
        return events
```
 
 
### Parser 16 — NginxAccessParser
 
 
```
# parsers/nginx_access_parser.py
# Pfad: /var/log/nginx/access.log
# Format: identisch mit Apache CLF — gleichen Parser nutzen
 
class NginxAccessParser(ApacheAccessParser):  # Erbt von Apache
    name = 'nginx_access'
    file_patterns = ['nginx/access.log', 'nginx/access.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return 'nginx' in str(path) and 'access' in path.name
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = super().parse(path)
        for e in events: e.source = 'nginx_access'
        return events
```
 
 
### Parser 17 — NginxErrorParser
 
 
```
# parsers/nginx_error_parser.py
# Format: '2026/04/22 09:15:33 [error] 1234#0: message'
NGINX_ERR = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+\[(?P<level>\w+)\]\s+\d+#\d+:\s+(?P<msg>.+)$'
)
 
class NginxErrorParser(BaseParser):
    name = 'nginx_error'
    file_patterns = ['nginx/error.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'nginx' in str(path) and 'error' in path.name
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {'emerg':'critical','alert':'critical','crit':'high',
                     'error':'high','warn':'medium','notice':'info','info':'info'}
        for line in self.read_lines(path):
            m = NGINX_ERR.match(line)
            if not m: continue
            events.append(self.make_event(
                m['ts'], 'nginx_error', 'http_error', m['msg'],
                severity=LEVEL_MAP.get(m['level'].lower(), 'info')
            ))
        return events
```
 
 
 
 
## 10.4 Datenbank-Logs (3 Parser)
 
 
### Parser 18 — MySQLErrorParser
 
 
```
# parsers/mysql_parser.py
# Pfad: /var/log/mysql/error.log
# Format: '2026-04-22T09:15:33.123456Z 0 [ERROR] message'
MYSQL_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)'
    r'\s+\d+\s+\[(?P<level>\w+)\]\s+(?P<msg>.+)$'
)
 
class MySQLErrorParser(BaseParser):
    name = 'mysql'
    file_patterns = ['mysql/error.log', 'mysql.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'mysql' in str(path).lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {'ERROR':'high','WARNING':'medium','NOTE':'info','System':'info'}
        for line in self.read_lines(path):
            m = MYSQL_PATTERN.match(line)
            if not m: continue
            events.append(self.make_event(
                m['ts'], 'mysql', 'db_event', m['msg'],
                severity=LEVEL_MAP.get(m['level'], 'info')
            ))
        return events
```
 
 
### Parser 19 — PostgreSQLParser
 
 
```
# parsers/postgresql_parser.py
# Pfad: /var/log/postgresql/postgresql-*.log
# Format: '2026-04-22 09:15:33.123 UTC [1234] user@db ERROR: message'
PG_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \w+)'
    r'\s+\[(?P<pid>\d+)\](?:\s+(?P<user>\S+))?\s+(?P<level>\w+):\s+(?P<msg>.+)$'
)
 
class PostgreSQLParser(BaseParser):
    name = 'postgresql'
    file_patterns = ['postgresql-*.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'postgresql' in path.name.lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {'ERROR':'high','FATAL':'critical','PANIC':'critical',
                     'WARNING':'medium','LOG':'info','INFO':'info'}
        for line in self.read_lines(path):
            m = PG_PATTERN.match(line)
            if not m: continue
            events.append(self.make_event(
                m['ts'], 'postgresql', 'db_event', m['msg'],
                user=m.get('user'), severity=LEVEL_MAP.get(m['level'], 'info')
            ))
        return events
```
 
 
### Parser 20 — MongoDBParser
 
 
```
# parsers/mongodb_parser.py
# Pfad: /var/log/mongodb/mongod.log
# Format: JSON-Lines seit MongoDB 4.4
# Altes Format: '2026-04-22T09:15:33.123+0000 I NETWORK [conn1] message'
MONGO_OLD = re.compile(
    r'^(?P<ts>\S+)\s+(?P<sev>[IWEF])\s+(?P<component>\S+)'
    r'\s+\[(?P<ctx>[^\]]+)\]\s+(?P<msg>.+)$'
)
 
class MongoDBParser(BaseParser):
    name = 'mongodb'
    file_patterns = ['mongod.log', 'mongodb.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'mongo' in path.name.lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        LEVEL_MAP = {'I':'info','W':'medium','E':'high','F':'critical'}
        for line in self.read_lines(path):
            # Versuche JSON-Format (MongoDB 4.4+)
            try:
                entry = json.loads(line)
                ts  = entry.get('t', {}).get('$date', '')
                msg = entry.get('msg', '')
                sev = entry.get('s', 'I')
                events.append(self.make_event(
                    ts, 'mongodb', 'db_event', msg,
                    severity=LEVEL_MAP.get(sev, 'info')
                ))
                continue
            except json.JSONDecodeError:
                pass
            # Fallback: Altes Format
            m = MONGO_OLD.match(line)
            if m:
                events.append(self.make_event(
                    m['ts'], 'mongodb', 'db_event', m['msg'],
                    severity=LEVEL_MAP.get(m['sev'], 'info')
                ))
        return events
```
 
 
 
 
## 10.5 Security-Logs (4 Parser)
 
 
### Parser 21 — AuditParser
 
 
> **Wichtig**
 
>
> Pfad: /var/log/audit/audit.log
>
> Das Linux Audit Framework protokolliert: Syscalls, Datei-Zugriffe, Benutzer-Aktionen
>
> Format: 'type=SYSCALL msg=audit(timestamp:serial): key=value ...'
>
> Sehr viele Events — nur kritische extrahieren
 
 
 
```
# parsers/audit_parser.py
AUDIT_PATTERN = re.compile(
    r'^type=(?P<type>\S+)\s+msg=audit\((?P<ts>[\d.]+):\d+\):\s+(?P<rest>.+)$'
)
AUDIT_CRITICAL_TYPES = [
    'EXECVE','SYSCALL','USER_AUTH','USER_LOGIN','USER_CMD',
    'CRED_ACQ','CRED_DISP','ADD_USER','DEL_USER','MOD_USER',
    'ANOM_EXEC','ANOM_MK_EXE','ANOM_PROMISCUOUS',
]
 
class AuditParser(BaseParser):
    name = 'audit'
    file_patterns = ['audit/audit.log', 'audit.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'audit' in path.name.lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = AUDIT_PATTERN.match(line)
            if not m: continue
            audit_type = m['type']
            if audit_type not in AUDIT_CRITICAL_TYPES: continue
            ts = datetime.fromtimestamp(float(m['ts']), tz=timezone.utc)
            # Key-Value aus rest parsen
            kv = dict(re.findall(r'(\w+)=(\S+)', m['rest']))
            sev = 'high' if audit_type.startswith('ANOM') else 'medium'
            events.append(self.make_event(
                ts, 'audit', audit_type.lower(),
                f'Audit {audit_type}: {m["rest"][:200]}',
                user=kv.get('auid'), process=kv.get('exe'),
                severity=sev, raw=kv
            ))
        return events
```
 
 
### Parser 22 — Fail2BanParser
 
 
```
# parsers/fail2ban_parser.py
# Format: '2026-04-22 09:15:33,123 fail2ban.actions [INFO] Ban 1.2.3.4'
F2B_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+'
    r'\s+fail2ban\.\S+\s+\[\w+\]\s+(?P<action>Ban|Unban|Found)\s+(?P<ip>[\d.]+)'
)
 
class Fail2BanParser(BaseParser):
    name = 'fail2ban'
    file_patterns = ['fail2ban.log', 'fail2ban.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('fail2ban')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = F2B_PATTERN.search(line)
            if not m: continue
            sev = 'high' if m['action'] == 'Ban' else 'medium'
            events.append(self.make_event(
                m['ts'], 'fail2ban', f'f2b_{m["action"].lower()}',
                f'Fail2Ban {m["action"]}: {m["ip"]}',
                ip=m['ip'], severity=sev
            ))
        return events
```
 
 
### Parser 23 — UFWParser (Ubuntu Firewall)
 
 
```
# parsers/ufw_parser.py
# Format: Eingebettet in syslog/kern.log
# Erkennungsmuster: '[UFW BLOCK]' oder '[UFW ALLOW]'
UFW_PATTERN = re.compile(
    r'\[UFW (?P<action>\w+)\].*SRC=(?P<src>[\d.]+).*DST=(?P<dst>[\d.]+)'
    r'.*(?:SPT=(?P<sport>\d+))?.*(?:DPT=(?P<dport>\d+))?'
)
 
class UFWParser(BaseParser):
    name = 'ufw'
    file_patterns = ['ufw.log', 'ufw.log.*']
 
    def can_parse(self, path: Path) -> bool:
        return 'ufw' in path.name.lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = UFW_PATTERN.search(line)
            if not m: continue
            action = m['action']
            sev = 'medium' if action == 'BLOCK' else 'info'
            events.append(self.make_event(
                datetime.now(tz=timezone.utc),  # Aus Syslog-Teil extrahieren
                'ufw', f'ufw_{action.lower()}',
                f'UFW {action}: {m["src"]}:{m["sport"]} → {m["dst"]}:{m["dport"]}',
                ip=m['src'], severity=sev
            ))
        return events
```
 
 
### Parser 24 — CronParser
 
 
```
# parsers/cron_parser.py
# Pfad: /var/log/cron, /var/log/cron.log, eingebettet in syslog
# Erkennt: neue Jobs, ausgeführte Jobs, Fehler
CRON_EXEC = re.compile(r'\((?P<user>\S+)\) CMD \((?P<cmd>.+)\)')
CRON_EDIT = re.compile(r'\((?P<user>\S+)\) (BEGIN|END) EDIT')
CRON_NEW  = re.compile(r'\((?P<user>\S+)\) (LIST|REPLACE)')
 
class CronParser(BaseParser):
    name = 'cron'
    file_patterns = ['cron', 'cron.log', 'cron.*']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('cron')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        SUSPICIOUS_CMDS = ['/tmp','/dev/shm','wget','curl','nc','bash -i',
                           'python -c','perl -e','ruby -e','php -r']
        for line in self.read_lines(path):
            m_base = PATTERN.match(line)  # Syslog-Basis
            if not m_base: continue
            msg = m_base['msg']
            ts  = f'{datetime.now().year} {m_base["month"]} {m_base["day"]} {m_base["time"]}'
            m = CRON_EXEC.search(msg)
            if m:
                cmd = m['cmd']
                sev = 'high' if any(s in cmd for s in SUSPICIOUS_CMDS) else 'info'
                events.append(self.make_event(
                    ts, 'cron', 'cron_exec',
                    f'Cron-Job ausgeführt: User={m["user"]} CMD={cmd}',
                    user=m['user'], severity=sev
                ))
        return events
```
 
 
 
 
## 10.6 User-Aktivitäts-Logs (4 Parser)
 
 
### Parser 25 — BashHistoryParser
 
 
```
# parsers/bash_history_parser.py
# Pfad: /home/*/.bash_history, /root/.bash_history
# Format: Eine Zeile = ein Befehl (kein Timestamp in Standard-Bash)
# Mit Timestamp: '#1650000000
 command'
BASH_TS = re.compile(r'^#(?P<ts>\d{10})$')
SUSPICIOUS = ['wget','curl','nc ','ncat','socat','chmod 777',
              '/tmp/','base64 -d','eval','exec','rm -rf',
              'dd if=','python -c','perl -e','pkill','kill -9']
 
class BashHistoryParser(BaseParser):
    name = 'bash_history'
    file_patterns = ['.bash_history']
 
    def can_parse(self, path: Path) -> bool:
        return path.name == '.bash_history'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        lines = self.read_lines(path)
        current_ts = None
        for line in lines:
            m = BASH_TS.match(line)
            if m:
                current_ts = datetime.fromtimestamp(int(m['ts']), tz=timezone.utc)
                continue
            if not line.strip(): continue
            ts = current_ts or datetime.now(tz=timezone.utc)
            sev = 'high' if any(s in line for s in SUSPICIOUS) else 'info'
            # User aus Pfad extrahieren: /home/USERNAME/.bash_history
            user = path.parts[-2] if len(path.parts) >= 2 else 'unknown'
            events.append(self.make_event(
                ts, 'bash_history', 'shell_command', line.strip(),
                user=user, severity=sev
            ))
        return events
```
 
 
### Parser 26 — ZshHistoryParser
 
 
```
# parsers/zsh_history_parser.py
# Pfad: /home/*/.zsh_history
# Format: ': timestamp:0;command' oder nur 'command'
ZSH_PATTERN = re.compile(r'^: (?P<ts>\d+):\d+;(?P<cmd>.+)$')
 
class ZshHistoryParser(BashHistoryParser):  # Erbt Suspicious-Liste
    name = 'zsh_history'
    file_patterns = ['.zsh_history']
 
    def can_parse(self, path: Path) -> bool:
        return path.name == '.zsh_history'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        user = path.parts[-2] if len(path.parts) >= 2 else 'unknown'
        for line in self.read_lines(path):
            m = ZSH_PATTERN.match(line)
            if m:
                ts  = datetime.fromtimestamp(int(m['ts']), tz=timezone.utc)
                cmd = m['cmd']
            else:
                ts  = datetime.now(tz=timezone.utc)
                cmd = line.strip()
            if not cmd: continue
            sev = 'high' if any(s in cmd for s in self.SUSPICIOUS) else 'info'
            events.append(self.make_event(
                ts, 'zsh_history', 'shell_command', cmd,
                user=user, severity=sev
            ))
        return events
```
 
 
### Parser 27 — FishHistoryParser
 
 
```
# parsers/fish_history_parser.py
# Pfad: /home/*/.local/share/fish/fish_history
# Format: YAML-ähnlich: '- cmd: command
  when: timestamp'
class FishHistoryParser(BaseParser):
    name = 'fish_history'
    file_patterns = ['fish_history']
 
    def can_parse(self, path: Path) -> bool:
        return path.name == 'fish_history'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        content = path.read_text(errors='replace')
        # Einträge parsen: '- cmd: ...' gefolgt von '  when: ...'
        entries = re.findall(r'- cmd: (.+?)
\s+when: (\d+)', content, re.DOTALL)
        user = path.parts[-5] if len(path.parts) >= 5 else 'unknown'
        for cmd, ts_str in entries:
            ts  = datetime.fromtimestamp(int(ts_str), tz=timezone.utc)
            sev = 'high' if any(s in cmd for s in SUSPICIOUS) else 'info'
            events.append(self.make_event(
                ts, 'fish_history', 'shell_command', cmd.strip(),
                user=user, severity=sev
            ))
        return events
```
 
 
### Parser 28 — UtmpParser (Binär — aktive Sessions)
 
 
```
# parsers/utmp_parser.py
# Pfad: /var/run/utmp (aktuelle Sessions) — identisches Format wie wtmp
# Erbt direkt von WtmpParser — identisches Binärformat
 
class UtmpParser(WtmpParser):
    name = 'utmp'
    file_patterns = ['utmp']
 
    def can_parse(self, path: Path) -> bool:
        return path.name == 'utmp'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = super().parse(path)
        for e in events: e.source = 'utmp'
        return events
```
 
 
 
 
## 10.7 Netzwerk & Dienste-Logs (5 Parser)
 
 
### Parser 29 — SSHParser (aus auth.log extrahiert)
 
 
```
# parsers/ssh_parser.py
# SSH-Events sind in auth.log eingebettet — dieser Parser ist spezialisiert
# Erkennt zusätzlich: Port-Forwarding, Tunnel, X11-Forwarding
SSH_PATTERNS = {
    'accepted':   re.compile(r'Accepted (\S+) for (\S+) from ([\d.]+) port (\d+)'),
    'failed':     re.compile(r'Failed (\S+) for (\S+) from ([\d.]+) port (\d+)'),
    'disconnect': re.compile(r'Disconnected from (\S+) ([\d.]+) port (\d+)'),
    'tunnel':     re.compile(r'Accepted.*port.*forwarding'),
    'x11':        re.compile(r'X11 forwarding request failed'),
    'invalid':    re.compile(r'Invalid user (\S+) from ([\d.]+)'),
    'bruteforce': re.compile(r'message repeated (\d+) times'),
}
 
class SSHParser(BaseParser):
    name = 'ssh'
    file_patterns = ['auth.log', 'secure']  # Aus diesen Dateien
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            if 'sshd' not in line: continue  # Nur SSH-Zeilen
            for event_type, pattern in SSH_PATTERNS.items():
                m = pattern.search(line)
                if m:
                    sev = 'high' if event_type in ('failed','invalid','bruteforce') else 'medium'
                    events.append(self.make_event(
                        datetime.now(tz=timezone.utc), 'ssh', f'ssh_{event_type}',
                        line.strip(), severity=sev
                    ))
                    break
        return events
```
 
 
### Parser 30 — PostfixMailParser
 
 
```
# parsers/postfix_parser.py
# Pfad: /var/log/mail.log, /var/log/maillog
# Format: Syslog-Basis + Postfix-spezifische Felder
POSTFIX_STATUS = re.compile(
    r'status=(?P<status>\w+).*to=<(?P<to>[^>]+)>.*from=<(?P<from>[^>]*)>'
)
 
class PostfixMailParser(BaseParser):
    name = 'postfix'
    file_patterns = ['mail.log', 'maillog']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith(('mail.log', 'maillog'))
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            if 'postfix' not in line.lower(): continue
            m_base = PATTERN.match(line)
            if not m_base: continue
            msg = m_base['msg']
            m = POSTFIX_STATUS.search(msg)
            if m:
                sev = 'high' if m['status'] == 'bounced' else 'info'
                events.append(self.make_event(
                    f'{datetime.now().year} {m_base["month"]} {m_base["day"]} {m_base["time"]}',
                    'postfix', f'mail_{m["status"]}',
                    f'Mail: {m["from"]} → {m["to"]} Status={m["status"]}',
                    severity=sev
                ))
        return events
```
 
 
### Parser 31 — FTPParser
 
 
```
# parsers/ftp_parser.py
# Pfad: /var/log/vsftpd.log
# Format: 'Tue Apr 22 09:15:33 2026 [pid 1234] CONNECT: Client ::ffff:1.2.3.4'
FTP_PATTERN = re.compile(
    r'^\w+\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+'
    r'\[pid \d+\]\s+(?P<action>\S+):\s+(?P<msg>.+)$'
)
 
class FTPParser(BaseParser):
    name = 'ftp'
    file_patterns = ['vsftpd.log', 'proftpd.log', 'ftp.log']
 
    def can_parse(self, path: Path) -> bool:
        return any(x in path.name.lower() for x in ('vsftpd','proftpd','ftp'))
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = FTP_PATTERN.match(line)
            if not m: continue
            sev = 'high' if 'FAIL' in m['action'] else 'info'
            events.append(self.make_event(
                datetime.now(tz=timezone.utc), 'ftp',
                f'ftp_{m["action"].lower()}', m['msg'], severity=sev
            ))
        return events
```
 
 
### Parser 32 — SambaParser
 
 
```
# parsers/samba_parser.py
# Pfad: /var/log/samba/log.smbd, /var/log/samba/log.nmbd
# Format: '[YYYY/MM/DD hh:mm:ss.ms, N] source(file:line) message'
SAMBA_PATTERN = re.compile(
    r'^\[(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+),\s*\d+\]'
    r'\s+\S+\s+(?P<msg>.+)$'
)
 
class SambaParser(BaseParser):
    name = 'samba'
    file_patterns = ['samba/log.*', 'log.smbd', 'log.nmbd']
 
    def can_parse(self, path: Path) -> bool:
        return 'samba' in str(path).lower() or path.name.startswith('log.')
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = SAMBA_PATTERN.match(line)
            if not m: continue
            sev = 'high' if 'error' in m['msg'].lower() else 'info'
            events.append(self.make_event(
                m['ts'], 'samba', 'smb_event', m['msg'], severity=sev
            ))
        return events
```
 
 
### Parser 33 — OpenVPNParser
 
 
```
# parsers/openvpn_parser.py
# Pfad: /var/log/openvpn.log, /var/log/openvpn/
# Format: 'YYYY-MM-DD hh:mm:ss message'
VPN_PATTERN = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<msg>.+)$'
)
 
class OpenVPNParser(BaseParser):
    name = 'openvpn'
    file_patterns = ['openvpn.log', 'openvpn/*.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'openvpn' in path.name.lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            m = VPN_PATTERN.match(line)
            if not m: continue
            msg = m['msg']
            sev = 'high' if 'TLS Error' in msg or 'AUTH_FAILED' in msg else 'info'
            events.append(self.make_event(
                m['ts'], 'openvpn', 'vpn_event', msg, severity=sev
            ))
        return events
```
 
 
 
 
## 10.8 Container & Cloud-Logs (5 Parser)
 
 
### Parser 34 — DockerParser
 
 
```
# parsers/docker_parser.py
# Pfad: /var/lib/docker/containers/<id>/<id>-json.log
# Format: JSON-Lines mit 'log', 'stream', 'time'
 
class DockerParser(BaseParser):
    name = 'docker'
    file_patterns = ['*-json.log']
 
    def can_parse(self, path: Path) -> bool:
        return path.name.endswith('-json.log') or 'docker' in str(path)
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            try:
                entry = json.loads(line)
                ts  = entry.get('time', '')
                msg = entry.get('log', '').strip()
                if not msg: continue
                # Container-ID aus Pfad
                container_id = path.parent.name[:12]
                events.append(self.make_event(
                    ts, 'docker', 'container_log', msg,
                    process=f'container:{container_id}', severity='info'
                ))
            except json.JSONDecodeError:
                continue
        return events
```
 
 
### Parser 35 — ContainerdParser
 
 
```
# parsers/containerd_parser.py
# Pfad: /var/log/containerd.log
# Format: JSON-Lines (ähnlich Docker)
 
class ContainerdParser(BaseParser):
    name = 'containerd'
    file_patterns = ['containerd.log']
 
    def can_parse(self, path: Path) -> bool:
        return 'containerd' in path.name.lower()
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            try:
                entry = json.loads(line)
                ts  = entry.get('time', entry.get('ts', ''))
                msg = entry.get('msg', '')
                lvl = entry.get('level', 'info')
                sev = 'high' if lvl in ('error','fatal') else 'info'
                events.append(self.make_event(
                    ts, 'containerd', 'container_event', msg, severity=sev
                ))
            except json.JSONDecodeError:
                continue
        return events
```
 
 
### Parser 36 — IISLogParser (Windows-Images)
 
 
```
# parsers/iis_parser.py
# Pfad: C:/inetpub/logs/LogFiles/**/*.log
# Format: W3C Extended Log Format
# Beispiel: '2026-04-22 09:15:33 192.168.1.1 GET /path - 80 - 1.2.3.4 ... 200'
IIS_PATTERN = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+(?P<server>[\d.]+)\s+(?P<method>\S+)\s+(?P<path>\S+)'
    r'.*?(?P<client>[\d.]+).*?(?P<status>\d{3})'
)
 
class IISLogParser(BaseParser):
    name = 'iis'
    file_patterns = ['u_ex*.log']  # IIS-typisches Namensmuster
 
    def can_parse(self, path: Path) -> bool:
        return path.name.startswith('u_ex') and path.suffix == '.log'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        for line in self.read_lines(path):
            if line.startswith('#'): continue  # Header-Zeilen
            m = IIS_PATTERN.match(line)
            if not m: continue
            status = int(m['status'])
            sev = 'high' if status >= 500 else 'medium' if status >= 400 else 'info'
            events.append(self.make_event(
                f'{m["date"]} {m["time"]}', 'iis', 'http_request',
                f'{m["method"]} {m["path"]} → {status}',
                ip=m['client'], severity=sev
            ))
        return events
```
 
 
### Parser 37 — WindowsEVTXParser (via Hayabusa)
 
 
```
# parsers/evtx_parser.py
# EVTX wird NICHT direkt geparst — Hayabusa übernimmt das
# Dieser Parser liest den Hayabusa-Output (JSONL) ein
import subprocess, json
 
class EVTXParser(BaseParser):
    name = 'evtx'
    file_patterns = ['*.evtx']
    binary = True
 
    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == '.evtx'
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        output_file = path.with_suffix('.jsonl')
        # Hayabusa aufrufen
        try:
            subprocess.run([
                '/opt/hayabusa/hayabusa', 'json-timeline',
                '--file', str(path),
                '--output', str(output_file),
                '--min-level', 'medium',
                '--no-wizard',
            ], capture_output=True, timeout=300)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            log.warning(f'Hayabusa fehlgeschlagen: {e}')
            return []
        # Hayabusa-Output einlesen
        if output_file.exists():
            for line in output_file.read_text().splitlines():
                try:
                    entry = json.loads(line)
                    ts    = entry.get('Timestamp', '')
                    msg   = entry.get('Details', '')
                    level = entry.get('Level', 'info')
                    rule  = entry.get('RuleTitle', '')
                    LEVEL_MAP = {'critical':'critical','high':'high',
                                 'medium':'medium','low':'info','informational':'info'}
                    events.append(self.make_event(
                        ts, 'evtx', 'windows_event',
                        f'{rule}: {msg}',
                        severity=LEVEL_MAP.get(level.lower(), 'info'),
                        raw=entry
                    ))
                except json.JSONDecodeError:
                    continue
        return events
```
 
 
### Parser 38 — PlasaFallbackParser
 
 
```
# parsers/plaso_parser.py
# LETZTER FALLBACK — wenn kein anderer Parser die Datei erkennt
# Plaso kann fast alle Log-Formate lesen
import subprocess, json
 
class PlasaFallbackParser(BaseParser):
    name = 'plaso_fallback'
    file_patterns = ['*']  # Alles was sonst niemand parst
 
    def can_parse(self, path: Path) -> bool:
        return True  # Immer als Fallback
 
    def parse(self, path: Path) -> List[ForensicEvent]:
        events = []
        storage = path.with_suffix('.plaso')
        try:
            subprocess.run(['log2timeline.py', str(storage), str(path)],
                capture_output=True, timeout=600)
            result = subprocess.run(
                ['psort.py', '--output-format', 'json', str(storage)],
                capture_output=True, text=True, timeout=300
            )
            for line in result.stdout.splitlines():
                try:
                    entry = json.loads(line)
                    events.append(self.make_event(
                        entry.get('datetime',''), 'plaso',
                        entry.get('data_type','unknown'),
                        entry.get('message',''),
                        severity='info', raw=entry
                    ))
                except: continue
        except Exception as e:
            log.warning(f'Plaso Fallback fehlgeschlagen: {e}')
        return events
```
 
 
 
 
 
---
 
# 11. MITRE ATT&CK Mapping — Vollständige Implementierung
 
 
---
 
 
> **Variante: Lokal JSON (empfohlen)**
 
>
> ATT&CK v15 JSON einmalig herunterladen — kein Internet während der Analyse nötig
>
> Download: wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
>
> Speichern unter: dfir_pipeline/data/enterprise-attack-v15.json
>
> Dateigröße: ca. 80 MB — einmalig herunterladen
 
 
 
## 11.1 ATT&CK JSON laden
 
 
```
# stages/stage09_mitre.py
import json
from pathlib import Path
 
def load_attack_db(json_path: Path) -> dict:
    '''Lädt ATT&CK JSON und erstellt einen schnellen Lookup-Index'''
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
 
    techniques = {}
    for obj in data['objects']:
        if obj.get('type') != 'attack-pattern': continue
        if obj.get('revoked', False): continue  # Veraltete überspringen
 
        # External ID extrahieren (T1053.003)
        ext_id = ''
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                ext_id = ref.get('external_id', '')
                break
 
        if not ext_id: continue
 
        # Taktiken extrahieren
        tactics = [p['phase_name'] for p in obj.get('kill_chain_phases', [])
                   if p.get('kill_chain_name') == 'mitre-attack']
 
        techniques[ext_id] = {
            'id':          ext_id,
            'name':        obj.get('name', ''),
            'description': obj.get('description', '')[:500],
            'tactics':     tactics,
            'platforms':   obj.get('x_mitre_platforms', []),
        }
    return techniques
```
 
 
## 11.2 Keyword-Mapping Tabelle (80+ Techniken)
 
 
Jede Zeile = ein Keyword das in Events gesucht wird → T-Nummer zugeordnet. Groß-/Kleinschreibung wird ignoriert.
 
 
```
# stages/stage09_mitre.py — KEYWORD_MAP
# Format: 'keyword_im_event': ('T-Nummer', 'Confidence 0.0-1.0')
 
KEYWORD_MAP = {
    # T1053 — Scheduled Task / Job
    'cron':          ('T1053.003', 0.7),
    'crontab':       ('T1053.003', 0.8),
    '/etc/cron':     ('T1053.003', 0.9),
    'at command':    ('T1053.001', 0.8),
    'systemd timer': ('T1053.006', 0.8),
 
    # T1070 — Indicator Removal
    'log deleted':   ('T1070.002', 0.9),
    'history -c':    ('T1070.003', 0.95),
    'rm .bash_history': ('T1070.003', 0.95),
    'shred':         ('T1070.004', 0.9),
    'wipe':          ('T1070.004', 0.8),
    'unset histfile':('T1070.003', 0.95),
 
    # T1078 — Valid Accounts
    'accepted password': ('T1078', 0.6),
    'accepted publickey': ('T1078', 0.6),
    'su root':       ('T1078.003', 0.8),
    'sudo su':       ('T1078.003', 0.8),
 
    # T1059 — Command and Scripting Interpreter
    '/bin/bash -i':  ('T1059.004', 0.95),
    'bash -c':       ('T1059.004', 0.8),
    'python -c':     ('T1059.006', 0.85),
    'perl -e':       ('T1059.006', 0.85),
    'ruby -e':       ('T1059.006', 0.85),
    'php -r':        ('T1059.006', 0.85),
 
    # T1105 — Ingress Tool Transfer
    'wget http':     ('T1105', 0.7),
    'curl -o':       ('T1105', 0.7),
    'scp ':          ('T1105', 0.6),
    'rsync ':        ('T1105', 0.5),
    'tftp ':         ('T1105', 0.8),
 
    # T1003 — OS Credential Dumping
    '/etc/shadow':   ('T1003.008', 0.9),
    '/etc/passwd':   ('T1003.008', 0.7),
    'hashdump':      ('T1003', 0.95),
    'mimikatz':      ('T1003.001', 0.99),
 
    # T1098 — Account Manipulation
    'useradd':       ('T1098', 0.8),
    'usermod':       ('T1098', 0.7),
    'passwd ':       ('T1098', 0.6),
    'new user':      ('T1098', 0.8),
    'visudo':        ('T1098', 0.85),
 
    # T1543 — Create or Modify System Process
    'systemctl enable': ('T1543.002', 0.8),
    'systemctl start':  ('T1543.002', 0.5),
    '/etc/init.d':   ('T1543.002', 0.7),
    'update-rc.d':   ('T1543.002', 0.8),
 
    # T1562 — Impair Defenses
    'ufw disable':   ('T1562.004', 0.95),
    'iptables -f':   ('T1562.004', 0.9),
    'setenforce 0':  ('T1562.006', 0.99),
    'systemctl stop ufw': ('T1562.004', 0.95),
    'service fail2ban stop': ('T1562', 0.9),
 
    # T1110 — Brute Force
    'failed password': ('T1110.001', 0.8),
    'authentication failure': ('T1110', 0.8),
    'invalid user':  ('T1110.003', 0.85),
 
    # T1071 — Application Layer Protocol
    'irc':           ('T1071.003', 0.7),
    'c2':            ('T1071', 0.6),
 
    # T1048 — Exfiltration Over Alternative Protocol
    'scp -r':        ('T1048', 0.7),
    'ftp put':       ('T1048', 0.8),
 
    # T1014 — Rootkit
    'insmod':        ('T1014', 0.7),
    'modprobe':      ('T1014', 0.5),
    'lkm':           ('T1014', 0.8),
 
    # T1083 — File and Directory Discovery
    'find / -name':  ('T1083', 0.6),
    'ls -la /etc':   ('T1083', 0.5),
 
    # T1222 — File and Directory Permissions Modification
    'chmod 777':     ('T1222', 0.8),
    'chmod +s':      ('T1222', 0.9),  # SUID setzen
    'chown root':    ('T1222', 0.7),
 
    # T1055 — Process Injection
    'ptrace':        ('T1055', 0.8),
    '/proc/*/mem':   ('T1055', 0.9),
 
    # T1136 — Create Account
    'adduser':       ('T1136.001', 0.85),
    'useradd -m':    ('T1136.001', 0.85),
 
    # T1190 — Exploit Public-Facing Application
    'union select':  ('T1190', 0.9),   # SQL Injection
    '../../../':     ('T1190', 0.85),  # Path Traversal
    '<script>':      ('T1190', 0.85),  # XSS
 
    # T1021 — Remote Services
    'rdp':           ('T1021.001', 0.7),
    'vnc':           ('T1021.005', 0.7),
    'telnet':        ('T1021', 0.8),
 
    # T1547 — Boot or Logon Autostart
    '.bashrc':       ('T1547.006', 0.7),
    '.profile':      ('T1547.006', 0.7),
    '/etc/profile':  ('T1547.006', 0.8),
 
    # T1027 — Obfuscated Files
    'base64 -d':     ('T1027', 0.85),
    'base64 --decode': ('T1027', 0.85),
    'xxd -r':        ('T1027', 0.8),
 
    # T1040 — Network Sniffing
    'tcpdump':       ('T1040', 0.7),
    'wireshark':     ('T1040', 0.6),
    'tshark':        ('T1040', 0.6),
}
```
 
 
## 11.3 Mapping-Funktion
 
 
```
def map_events_to_mitre(events: List[ForensicEvent],
                         techniques: dict) -> List[dict]:
    '''Mappt Events auf MITRE ATT&CK Techniken via Keyword-Matching'''
    hits = []
    for event in events:
        msg_lower = event.message.lower()
        for keyword, (tech_id, confidence) in KEYWORD_MAP.items():
            if keyword.lower() in msg_lower:
                tech = techniques.get(tech_id, {})
                hits.append({
                    'technique_id':   tech_id,
                    'technique_name': tech.get('name', 'Unbekannt'),
                    'tactics':        tech.get('tactics', []),
                    'confidence':     confidence,
                    'event_timestamp': event.timestamp.isoformat(),
                    'event_message':  event.message[:300],
                    'event_source':   event.source,
                    'keyword_matched': keyword,
                })
                event.mitre_tags.append(tech_id)
                break  # Pro Event nur eine Technik
    # Deduplizieren: gleiche Technik nur einmal pro Stunde
    return deduplicate_hits(hits)
```
 
 
 
 
 
---
 
# 12. YARA & Sigma Regeln — Öffentliche Standard-Regeln
 
 
---
 
 
## 12.1 YARA-Regeln (für Anti-Forensics-Erkennung)
 
 
> **Quelle: Öffentliche Standard-Regeln**
 
>
> Repo: https://github.com/Yara-Rules/rules (Community YARA Rules)
>
> Repo: https://github.com/Neo23x0/signature-base (Florian Roth)
>
> Installation: pip install yara-python
>
> Regeln herunterladen: git clone https://github.com/Yara-Rules/rules data/yara-rules/
>
> Verwendete Kategorien: malware/, antidebug_antivm/, exploit_kits/
 
 
 
```
# stages/stage07_antiforensics.py
import yara
from pathlib import Path
 
def load_yara_rules(rules_dir: Path) -> yara.Rules:
    '''Lädt alle YARA-Regeln aus dem Verzeichnis'''
    rule_files = {}
    for yar_file in rules_dir.rglob('*.yar'):
        rule_files[yar_file.stem] = str(yar_file)
    return yara.compile(filepaths=rule_files)
 
def scan_file_with_yara(file_path: Path, rules: yara.Rules) -> List[dict]:
    '''Scannt eine einzelne Datei mit YARA-Regeln'''
    hits = []
    try:
        matches = rules.match(str(file_path), timeout=30)
        for match in matches:
            hits.append({
                'rule':     match.rule,
                'tags':     match.tags,
                'file':     str(file_path),
                'strings':  [(s.identifier, s.offset) for s in match.strings],
            })
    except yara.TimeoutError:
        log.warning(f'YARA Timeout für {file_path}')
    except yara.Error as e:
        log.warning(f'YARA Fehler: {e}')
    return hits
 
# Anti-Forensics spezifische YARA-Regeln (zusätzlich zu Community-Regeln):
CUSTOM_ANTIFORENSICS_RULES = '''
rule Timestomping_Indicator {
    meta:
        description = 'Erkennt Timestomping-Tools'
    strings:
        $s1 = 'SetFileTime' ascii
        $s2 = 'touch -t' ascii
        $s3 = 'timestomp' ascii nocase
    condition: any of them
}
 
rule LogWiping_Indicator {
    meta:
        description = 'Erkennt Log-Löschungs-Muster'
    strings:
        $s1 = '> /var/log' ascii
        $s2 = 'truncate -s 0' ascii
        $s3 = 'rm -f /var/log' ascii
        $s4 = 'echo "" > /var/log' ascii
    condition: any of them
}
'''
```
 
 
## 12.2 Sigma-Regeln (für Hayabusa/EVTX)
 
 
> **Quelle: Offizielle Sigma-Regeln**
 
>
> Repo: https://github.com/SigmaHQ/sigma
>
> Installation: git clone https://github.com/SigmaHQ/sigma data/sigma-rules/
>
> Hayabusa nutzt diese Regeln automatisch wenn der Pfad konfiguriert ist
>
> Relevante Unterordner: rules/windows/ (für Windows-Images)
 
 
 
```
# In config.yaml konfigurieren:
hayabusa:
  binary:     '/opt/hayabusa/hayabusa'
  rules_dir:  'data/sigma-rules/rules/windows'
  min_level:  'medium'  # low, medium, high, critical
 
# In stage03_logs.py — Hayabusa mit Sigma-Regeln aufrufen:
subprocess.run([
    cfg.hayabusa_binary,
    'json-timeline',
    '--directory', str(evtx_dir),
    '--rules',     str(sigma_rules_dir),
    '--output',    str(output_file),
    '--min-level', cfg.min_level,
    '--no-wizard',
    '--quiet',
], capture_output=True, timeout=600)
```
 
 
 
 
 
---
 
# 13. Parser-Router — Automatische Datei-Erkennung
 
 
---
 
 
Der Parser-Router entscheidet welcher Parser für welche Datei zuständig ist. Er wird in Stufe 3 aufgerufen und iteriert über alle gefundenen Log-Dateien im Image.
 
 
```
# stages/stage03_logs.py — ParserRouter
from parsers import (  # Alle Parser importieren
    SyslogParser, AuthLogParser, JournaldParser, KernLogParser,
    BootLogParser, DaemonLogParser, WtmpParser, LastlogParser,
    DpkgParser, AptHistoryParser, YumParser, DnfParser, PacmanParser,
    ApacheAccessParser, ApacheErrorParser, NginxAccessParser, NginxErrorParser,
    MySQLErrorParser, PostgreSQLParser, MongoDBParser,
    AuditParser, Fail2BanParser, UFWParser, CronParser,
    BashHistoryParser, ZshHistoryParser, FishHistoryParser, UtmpParser,
    SSHParser, PostfixMailParser, FTPParser, SambaParser, OpenVPNParser,
    DockerParser, ContainerdParser, IISLogParser, EVTXParser,
    PlasaFallbackParser,
)
 
# Reihenfolge ist wichtig — spezifischere Parser zuerst!
ALL_PARSERS = [
    JournaldParser(),    # Binär — zuerst prüfen
    WtmpParser(),        # Binär
    UtmpParser(),        # Binär
    LastlogParser(),     # Binär
    EVTXParser(),        # Binär — Hayabusa
    AuthLogParser(),     # Vor SyslogParser (spezifischer)
    SSHParser(),         # Vor SyslogParser
    CronParser(),        # Vor SyslogParser
    AuditParser(),
    Fail2BanParser(),
    UFWParser(),
    KernLogParser(),
    BootLogParser(),
    DaemonLogParser(),
    SyslogParser(),      # Generisch — nach spezifischen
    DpkgParser(),
    AptHistoryParser(),
    YumParser(),
    DnfParser(),
    PacmanParser(),
    ApacheAccessParser(),
    ApacheErrorParser(),
    NginxAccessParser(),
    NginxErrorParser(),
    MySQLErrorParser(),
    PostgreSQLParser(),
    MongoDBParser(),
    BashHistoryParser(),
    ZshHistoryParser(),
    FishHistoryParser(),
    PostfixMailParser(),
    FTPParser(),
    SambaParser(),
    OpenVPNParser(),
    DockerParser(),
    ContainerdParser(),
    IISLogParser(),
    PlasaFallbackParser(),  # IMMER LETZTER
]
 
def route_and_parse(log_file: Path) -> List[ForensicEvent]:
    '''Findet den richtigen Parser und parst die Datei'''
    for parser in ALL_PARSERS:
        if parser.name == 'plaso_fallback': continue  # Fallback überspringen
        if parser.can_parse(log_file):
            log.info(f'Parser {parser.name} → {log_file.name}')
            return parser.safe_parse(log_file)
    # Kein Parser gefunden — Plaso als Fallback
    log.info(f'Plaso Fallback → {log_file.name}')
    return PlasaFallbackParser().safe_parse(log_file)
```
 
 
 
 
 
---
 
# 14. Vollständige requirements.txt
 
 
---
 
 
```
# requirements.txt — EXAKTE VERSIONEN für reproduzierbare Installation
 
# ── Forensik-Frameworks ──────────────────────────────────────
dissect==5.0.0                    # Disk-Image Analyse
volatility3==2.5.0                # RAM-Dump Analyse
 
# ── Log-Parsing ──────────────────────────────────────────────
python-evtx==0.7.4                # EVTX direkt lesen (Fallback)
construct==2.10.68                # Binär-Strukturen parsen
 
# ── YARA ─────────────────────────────────────────────────────
yara-python==4.3.1                # YARA-Regeln ausführen
 
# ── ML ───────────────────────────────────────────────────────
scikit-learn==1.4.0               # Isolation Forest
numpy==1.26.4                     # Numerische Berechnungen
pandas==2.2.0                     # Datennormalisierung
 
# ── Timestamp & Datum ────────────────────────────────────────
python-dateutil==2.9.0            # Timestamp-Parsing
pytz==2024.1                      # Zeitzone-Konvertierung
 
# ── Datei-Erkennung ──────────────────────────────────────────
python-magic==0.4.27              # Dateityp-Erkennung
 
# ── PDF-Erstellung ───────────────────────────────────────────
reportlab==4.1.0                  # PDF generieren
 
# ── Timesketch ───────────────────────────────────────────────
timesketch-api-client==20240101   # Timesketch Upload
 
# ── MITRE ATT&CK ─────────────────────────────────────────────
attackcti==0.3.4                  # ATT&CK API (für Updates)
 
# ── Datenbank ────────────────────────────────────────────────
duckdb>=0.10.0                    # Event-Store (RAM-Entlastung, skalierbar bis 4 TB)

# ── Konfiguration ────────────────────────────────────────────
pyyaml==6.0.1                     # config.yaml lesen
 
# ── HTTP & Download ──────────────────────────────────────────
requests==2.31.0                  # HTTP-Requests
urllib3==2.2.0                    # HTTP-Client
 
# ── Hashing ──────────────────────────────────────────────────
# hashlib ist Standard-Bibliothek — kein pip install nötig
 
# ── Komprimierung ────────────────────────────────────────────
# gzip, zipfile sind Standard-Bibliothek — kein pip install nötig
 
# ── Testing ──────────────────────────────────────────────────
pytest==8.1.0                     # Unit Tests
pytest-cov==4.1.0                 # Test-Coverage
```
 
 
## 14.1 Einmalige Setup-Befehle (nach Installation)
 
 
```
# 1. MITRE ATT&CK v15 herunterladen (einmalig)
mkdir -p data
wget -O data/enterprise-attack-v15.json \
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
 
# 2. YARA Community-Regeln herunterladen (einmalig)
git clone https://github.com/Yara-Rules/rules data/yara-rules/
git clone https://github.com/Neo23x0/signature-base data/yara-rules/signature-base/
 
# 3. Sigma-Regeln herunterladen (einmalig)
git clone https://github.com/SigmaHQ/sigma data/sigma-rules/
 
# 4. Hayabusa herunterladen
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux.zip
unzip hayabusa-linux.zip -d /opt/hayabusa/
chmod +x /opt/hayabusa/hayabusa
 
# 5. Zimmerman Tools via Wine (optional für Windows-Artefakte)
wget https://f001.backblazeb2.com/file/EricZimmermanTools/net6/All_6.zip
unzip All_6.zip -d /opt/zimmerman/
 
# 6. Timesketch starten
docker-compose up -d
 
# 7. Verzeichnisstruktur prüfen
ls data/
# enterprise-attack-v15.json  yara-rules/  sigma-rules/
```
 
 
---
---
 
**Ende des vollständigen Pflichtenhefts v3.0 — Claude Code Ready**
 
Alle 38 Parser, MITRE-Mapping, YARA, Sigma, Datenmodelle und Schemas vollständig dokumentiert.