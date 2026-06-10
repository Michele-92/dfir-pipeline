# 4 Systemarchitektur und Design

Die in Kapitel 3 formulierten Anforderungen — vollständige Automatisierung, forensische Integrität, Erweiterbarkeit und lokale Verarbeitung — bilden den unmittelbaren Rahmen für alle Architektur- und Designentscheidungen dieses Kapitels. Kapitel 4 beschreibt, wie die DFIR-Analysepipeline strukturell aufgebaut ist, welche Komponenten zusammenwirken, auf welchen Technologien das System basiert und mit welcher Begründung zentrale Designentscheidungen getroffen wurden.

Die Architektur folgt drei übergeordneten Leitprinzipien: **Modularität** — jede Analysefunktion ist eine eigenständige, austauschbare Einheit; **forensische Integrität** — jeder Verarbeitungsschritt wird protokolliert und ist nachvollziehbar; sowie **konfigurierte Automatisierung** — das System ist vollständig automatisiert betreibbar, erlaubt aber gezielte Eingriffe durch Parameter auf Analyse- und Infrastrukturebene.

---

## 4.1 Überblick der Gesamtarchitektur

Die DFIR-Analysepipeline ist als sequenzielle Verarbeitungskette konzipiert, in der ein Disk-Image — optional ergänzt durch einen RAM-Dump — als Eingabe dient und am Ende ein strukturierter forensischer Analysebericht ausgegeben wird. Die Verarbeitung erfolgt in elf aktiven Analyse-Stages, die nacheinander ausgeführt werden und dabei ein gemeinsames zentrales Datenobjekt — den `PipelineContext` — schrittweise mit Befunden anreichern.

Abbildung 4.1 zeigt den Gesamtfluss der Pipeline mit allen aktiven Verarbeitungsstufen, dem zentralen Datenspeicher (EventStore auf Basis von DuckDB) sowie den eingesetzten externen Werkzeugen.

> **Abbildung 4.1:** Architekturübersicht der DFIR-Analysepipeline — aktive Stages, Datenfluss und externe Tool-Abhängigkeiten.
> *(Quelle: Autor, 2026 — Diagramm aus docs/pipeline_diagram_slim.mmd)*

Der Verarbeitungsfluss beginnt mit **Stage 01** (automatische Dateierkennung und Beweissicherung), die das Eingabe-Image identifiziert, dessen kryptografische Hashwerte berechnet und die Ordnerstruktur für den Analysefall anlegt. Anschließend analysiert **Stage 02** optional einen RAM-Dump mittels Volatility3, bevor **Stage 02** (Partition-Layout) die Partitionstabelle des Disk-Images einliest und die analysefähigen Partitionen bestimmt. **Stage 03** (System-Profiling) ermittelt Betriebssystem, Kernel-Version, Netzwerkkonfiguration und Nutzerprofil des untersuchten Systems.

Mit **Stage 05** erfolgt die eigentliche Dateisystem-Extraktion über The Sleuth Kit: gelöschte Dateien werden wiederhergestellt, extrahierte Dateien gehasht und eine MACtime-Zeitlinie für die Partition erstellt. **Stage 03.5** (Basic Checks) prüft anschließend die Konsistenz der Log-Infrastruktur des Images — fehlende oder manipulierte Protokolldateien werden als Anomalie markiert. In **Stage 06** werden alle extrahierten Log-Dateien durch 38 spezialisierte Parser verarbeitet; die normalisierten Events werden in eine DuckDB-Datenbank geschrieben. Parallel dazu extrahiert **Stage 07** Indicators of Compromise (IOCs) aus dem Rohmaterial mittels regulärer Ausdrücke.

**Stage 08** normalisiert alle Zeitstempel auf UTC und korrigiert fehlerhafte oder fehlende Felder in der Datenbank. **Stage 09** prüft das gesamte Analysematerial auf Indikatoren für Anti-Forensics-Techniken, darunter Log-Wipes, Timestomping und Rootkit-Spuren. Abschließend bewertet **Stage 13** die Gesamtqualität des Analysedurchlaufs anhand aufgetretener Fehler und Warnungen, bevor **Stage 14** sämtliche Ergebnisse in einen PDF-Report, JSON-Exporte und ein Chain-of-Custody-Dokument überführt sowie optional in Timesketch hochlädt.

Ein zentrales architektonisches Merkmal ist die **Fehlertoleranz (Graceful Degradation)**: Tritt in einer Stage ein Fehler auf — etwa weil ein externes Tool nicht installiert ist oder ein Eingabeformat nicht unterstützt wird —, wird dieser Fehler im `PipelineContext` protokolliert und die Pipeline läuft mit allen verbleibenden Stages weiter. Jede Stage operiert damit unabhängig vom Ergebnis der Vorgängerstufe. Stage 13 dokumentiert am Ende alle aufgetretenen Fehler und spiegelt sie im Qualitätsurteil wider. Dieses Prinzip ist für forensische Einsatzszenarien entscheidend: Ein fehlendes RAM-Image darf nicht dazu führen, dass keine Log-Analyse stattfindet.

Die **Systemgrenzen** der Pipeline sind klar definiert: Die Pipeline empfängt ein forensisch gesichertes Disk-Image und liefert einen Analysebericht. Sie ersetzt nicht die manuelle Dokumentation der Beweiskette vor und nach dem Analyseprozess (Sicherstellung, Transport, Übergabe). Das Pipeline-Ausführungsprotokoll deckt ausschließlich die digitale Analysephase ab, nicht die vollständige Chain of Custody im rechtlichen Sinne.

---

## 4.2 Komponentenübersicht

Das System gliedert sich in acht logische Komponenten, die jeweils eine klar abgegrenzte Verantwortlichkeit übernehmen. Tabelle 4.1 gibt einen strukturierten Überblick; die nachfolgenden Abschnitte beschreiben jede Komponente im Detail.

**Tabelle 4.1:** Komponentenübersicht der DFIR-Analysepipeline

| Komponente | Verzeichnis / Datei | Verantwortlichkeit |
|---|---|---|
| Orchestrierung | `pipeline.py` | CLI-Einstiegspunkt, Stage-Ausführung, Fehlerbehandlung |
| Stage-Module | `stages/*.py` | 11 aktive Analyse-Stufen |
| Datenmodelle | `models/` | PipelineContext, ForensicEvent, IOC, ChainOfCustody |
| Hilfsfunktionen | `utils/` | EventStore, Timestamp-Konvertierung, Hashing, Terminal-UI |
| Log-Parser | `parsers/` | 38 spezialisierte Parser mit gemeinsamer Basisklasse |
| Statische Daten | `data/` | YARA-Signaturen, Sigma-Regeln |
| Konfiguration | `config.yaml` + CLI | Infrastruktur- und Ausführungsparameter |
| Deployment | `docker-compose.yml` | Timesketch + Elasticsearch |

**Orchestrierung (`pipeline.py`):** Die Datei `pipeline.py` ist der einzige Einstiegspunkt des Systems. Sie parst die CLI-Argumente, initialisiert den `PipelineContext` und ruft die Stage-Module in festgelegter Reihenfolge über die zentrale Funktion `run_stage()` auf. `run_stage()` kapselt jeden Stage-Aufruf in einer Fehlerbehandlungsroutine und kümmert sich um die CoC-Protokollierung sowie die Aktualisierung der Terminal-Anzeige. Die Orchestrierungsschicht kennt die internen Implementierungen der Stages nicht — sie ruft ausschließlich die einheitliche `run(ctx)`-Schnittstelle auf.

**Stage-Module (`stages/*.py`):** Jede Analyse-Stage ist als eigenständiges Python-Modul implementiert. Die öffentliche Schnittstelle jedes Moduls besteht aus einer einzigen Funktion `run(ctx: PipelineContext) -> PipelineContext`, die den angereicherten Kontext zurückgibt. Diese Konvention ermöglicht es, einzelne Stages isoliert zu testen, zu ersetzen oder zu deaktivieren, ohne andere Teile des Systems zu berühren. Die Stage-Module kennen sich gegenseitig nicht und kommunizieren ausschließlich über den gemeinsamen `PipelineContext`.

**Datenmodelle (`models/`):** Das Verzeichnis `models/` enthält alle zentralen Datenklassen des Systems. Der `PipelineContext` hält den gesamten Analysezustand. `ForensicEvent` repräsentiert ein einzelnes normalisiertes Log-Ereignis. `IOC` kapselt einen extrahierten Indicator of Compromise mit Typ, Wert und Quellangabe. `ChainOfCustody` dokumentiert den Ablauf der Analysephase als sequenzielle Protokolleinträge. Die Trennung von Datenmodellen und Verarbeitungslogik in separate Verzeichnisse folgt dem Prinzip der Separation of Concerns und vereinfacht die Wiederverwendung der Modelle in verschiedenen Kontexten — etwa in Tests oder in der Report-Generierung.

**Hilfsfunktionen (`utils/`):** Das `utils/`-Verzeichnis bündelt technische Querschnittsfunktionen. Der `EventStore` abstrahiert den Zugriff auf die DuckDB-Datenbank. `timestamp.py` stellt die Funktion `to_utc()` bereit, die Zeitstempel aus beliebigen Formaten in UTC konvertiert. `hashing.py` berechnet SHA256 und MD5 über einen 64-KB-Stream, um auch bei sehr großen Dateien (100 GB bis 1 TB) keinen RAM-Überlauf zu verursachen. `rich_ui.py` kapselt die Terminal-Ausgabe auf Basis der `rich`-Bibliothek.

**Log-Parser (`parsers/`):** Die 38 spezialisierten Log-Parser sind von einer gemeinsamen abstrakten Basisklasse `BaseParser` abgeleitet, die die Schnittstellen `can_parse(file_path)` und `parse(file_path)` vorschreibt. `can_parse()` wird von der Routing-Logik in Stage 06 aufgerufen, um automatisch den richtigen Parser für eine gegebene Log-Datei zu bestimmen. Jeder Parser gibt eine Liste von `ForensicEvent`-Objekten zurück, sodass Stage 06 und alle nachgelagerten Stages formatunabhängig mit einem einheitlichen Ereignisschema arbeiten.

**Statische Daten (`data/`):** Das `data/`-Verzeichnis enthält versionierte Regelwerke: YARA-Community-Regeln für Stage 09 (Anti-Forensics-Erkennung) sowie Sigma-Regeln für die optionale Hayabusa-gestützte EVTX-Analyse in Stage 06. Diese Daten sind bewusst im Repository versioniert, um reproduzierbare Analyseergebnisse zu gewährleisten — eine abweichende Regelversion würde bei gleichen Eingabedaten zu anderen Befunden führen.

**Konfiguration:** Die Konfiguration des Systems erfolgt zweistufig. Die Datei `config.yaml` enthält persistente Infrastrukturparameter wie die Timesketch-Verbindungsdaten, den Pfad zum Hayabusa-Binary und die ML-Schwellenwerte. CLI-Parameter bei der Ausführung von `pipeline.py` steuern analysespezifische Optionen wie den Betriebsmodus (`--mode auto|manual`), die YARA-Regelauswahl (`--yara custom|linux|full`) und die Anzahl paralleler Worker (`--workers N`). Die Zweistufigkeit trennt Umgebungskonfiguration (selten geändert) von Analyseparametern (per Lauf variabel).

---

## 4.3 Datenfluss und PipelineContext

### 4.3.1 PipelineContext als zentrales Datenobjekt

Das architektonische Herzstück der Pipeline ist der `PipelineContext` — eine Python-`@dataclass`, die den vollständigen Zustand einer laufenden oder abgeschlossenen Analyse hält. Alle elf aktiven Stages empfangen dasselbe `ctx`-Objekt, reichern es mit ihren Ergebnissen an und geben es zurück. Der Orchestrierungsrahmen in `pipeline.py` übergibt das angereicherte Objekt an die jeweils nächste Stage.

```python
# Auszug aus models/pipeline_context.py
@dataclass
class PipelineContext:
    # ── Eingabe ──────────────────────────────────────────
    disk_image_path:  Optional[Path] = None
    ram_dump_path:    Optional[Path] = None
    output_dir:       Path = field(default_factory=lambda: Path('./output'))

    # ── Stage 01: Dateierkennung ──────────────────────────
    file_type:    str   = ''   # 'E01', 'DD', 'VMDK', ...
    sha256:       str   = ''
    md5:          str   = ''
    file_size_gb: float = 0.0

    # ── Stage 03: System-Profiling ────────────────────────
    os_family:       str  = ''   # 'debian', 'rhel', 'arch'
    kernel_version:  str  = ''
    timezone:        str  = 'UTC'

    # ── Stage 06: Log-Parsing ─────────────────────────────
    events_db_path:  Optional[Path] = None  # DuckDB-Datei
    parsed_events:   int = 0

    # ── Stage 09: Anti-Forensics ──────────────────────────
    antiforensics_hits: List[Dict] = field(default_factory=list)

    # ── Metadaten ─────────────────────────────────────────
    stage_errors:  Dict[str, str] = field(default_factory=dict)
    stage_status:  Dict[str, str] = field(default_factory=dict)
    coc:           Optional[ChainOfCustody] = None
```

Der `PipelineContext` besitzt insgesamt rund 90 Felder, die sämtliche Eingaben, Zwischenergebnisse und Ausgaben der Pipeline abbilden. Die Verwendung eines einzelnen gemeinsamen Objekts anstelle von Nachrichtenwarteschlangen oder Event-Bussen hat mehrere Vorteile: Der Zustand der Analyse ist zu jedem Zeitpunkt vollständig introspektierbar, typsicher und direkt debuggbar. Da die Pipeline stets auf einem einzelnen Analyserechner läuft, ist kein verteiltes Kommunikationsprotokoll erforderlich. Eine Queue-basierte Architektur würde Serialisierung und Deserialisierung für komplexe verschachtelte Objekte erfordern und den Debugging-Aufwand erheblich erhöhen, ohne einen Mehrwert für den vorliegenden Einsatzkontext zu bieten.

### 4.3.2 EventStore und DuckDB als persistente Datenschicht

Eine besondere Herausforderung bei der Verarbeitung großer Disk-Images ist die schiere Menge an Log-Events: In Praxistests mit einem 5,7-GB-Image wurden über 120.000 IOCs und mehrere zehntausend normalisierte Events erzeugt; bei Images im Bereich von 100 GB bis 1 TB kann die Event-Anzahl auf mehrere Millionen anwachsen. Die naive Lösung — alle Events als Python-Liste im Arbeitsspeicher zu halten — würde bei solchen Datenmengen zu einem Programmabbruch durch Speichermangel führen.

Die Pipeline löst dieses Problem durch den **EventStore**, eine in `utils/event_store.py` implementierte Abstraktionsklasse, die DuckDB als eingebetteten Column-Store nutzt. DuckDB ist ein in-process analytisches Datenbanksystem, das ohne separaten Datenbankserver auskommt und direkt in den Python-Prozess eingebettet läuft. Stage 06 schreibt Events in Batches von 1.000 Einträgen in die Datenbank, ohne sie vollständig im RAM zu puffern. Nachgelagerte Stages lesen Events per SQL-Abfrage oder über einen Stream-Iterator.

```python
# Auszug aus utils/event_store.py
class EventStore:
    def insert_events(self, events: List[ForensicEvent]):
        rows = [(e.timestamp, e.source, e.event_type,
                 e.message, e.user, e.ip, e.process,
                 e.file_path, e.severity) for e in events]
        self._conn.executemany(
            "INSERT INTO events VALUES (nextval('events_id_seq'), ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, 0.0, '[]')", rows
        )
```

Das DuckDB-Schema speichert pro Event: Zeitstempel (indiziert), Quelle, Ereignistyp, Nachricht, Nutzername, IP-Adresse, Prozessname, Dateipfad, Schweregrad sowie reservierte Felder für Anomalie-Score und MITRE-Tags. Die Verwendung eines Column-Stores ist für Zeitreihenabfragen besonders effizient, da bei Filtern nach Zeitraum oder Schweregrad nur die jeweilige Spalte gelesen werden muss, nicht der vollständige Datensatz.

Stage 08 nutzt die SQL-Fähigkeit von DuckDB direkt für die Timestamp-Normalisierung: Anstatt alle Events ins RAM zu laden und in Python zu verarbeiten, führt Stage 08 ein SQL-`UPDATE` mit einer Python-UDF (User Defined Function) über den Gesamtdatensatz aus. Dies hält den Arbeitsspeicherverbrauch auch bei Millionen von Events konstant.

### 4.3.3 Chain of Custody als Protokollschicht

Jede Stage trägt nach ihrer Ausführung einen Eintrag in das `ChainOfCustody`-Objekt des `PipelineContext` ein. Dieses Objekt — implementiert in `models/chain_of_custody.py` — hält eine geordnete Liste von `CoCEntry`-Instanzen, die jeweils Stage-Name, ausgeführte Aktion und exakten UTC-Zeitstempel enthalten:

```python
# models/chain_of_custody.py
@dataclass
class CoCEntry:
    stage:     str
    action:    str
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ChainOfCustody:
    file_name:  str     # Name des analysierten Images
    sha256:     str     # Hash bei Analysebeginn
    md5:        str
    size_gb:    float
    start_time: datetime
    entries:    List[CoCEntry] = field(default_factory=list)
```

Die `ChainOfCustody`-Klasse speichert außerdem SHA256-Hashes aller von Stage 05 extrahierten Dateien, sodass die Integrität des Extraktionsergebnisses nachträglich verifiziert werden kann. Stage 14 exportiert das vollständige Protokoll als separates PDF-Dokument (`chain_of_custody.pdf`).

Es ist ausdrücklich festzuhalten, dass dieses Protokoll den **Analyseschritt** der forensischen Beweiskette dokumentiert, nicht die vollständige Chain of Custody im rechtlichen Sinne. Die übergeordnete Beweiskette — Sicherstellung, Transport, Übergabe und Langzeitarchivierung — liegt außerhalb des Systemumfangs und muss durch den Forensiker manuell geführt werden.

---

## 4.4 Technologie-Stack

### 4.4.1 Backend (Python)

Die Pipeline ist vollständig in Python 3.11 implementiert. Die Wahl von Python als primäre Implementierungssprache ist durch mehrere Faktoren begründet: Das forensische Werkzeug-Ökosystem — insbesondere Volatility3 und die Dissect-Bibliothek — bietet erstklassige Python-Bindings. Maschinelles Lernen und statistische Analyse sind über scikit-learn und NumPy ohne externe Dienste integrierbar. Die Report-Generierung mittels reportlab erlaubt vollständig programmgesteuerte PDF-Ausgabe ohne Abhängigkeit von Office-Anwendungen. Schließlich ermöglicht die Python-Ökosystemreife ein breites Spektrum bewährter Bibliotheken für alle Teilaufgaben der Pipeline.

Tabelle 4.2 listet die zentralen Python-Bibliotheken mit ihrer Version, ihrem Verwendungszweck und der Begründung ihrer Auswahl.

**Tabelle 4.2:** Kernbibliotheken des Python-Backends

| Bibliothek | Version | Zweck | Begründung |
|---|---|---|---|
| `python-magic` | 0.4.27 | Dateityp-Erkennung via Magic-Header | Zuverlässiger als Dateiendungsauswertung; erkennt auch umbenannte Images |
| `volatility3` | 2.5.0 | RAM-Analyse | Weit verbreitetes Framework für Memory Forensics; umfangreiche Plugin-Sammlung |
| `yara-python` | 4.3.1 | Signaturbasiertes Matching (Anti-Forensics, Malware) | Industriestandard; unterstützt Community-Regelsätze direkt |
| `scikit-learn` | 1.4.0 | ML-Algorithmen (Isolation Forest) | Stabile, dokumentierte API; kein Deep-Learning-Overhead erforderlich |
| `numpy` | 1.26.4 | Numerische Grundoperationen für ML | Standardabhängigkeit von scikit-learn |
| `duckdb` | ≥ 0.10.0 | Eingebetteter Column-Store für Events | RAM-effizient, SQL-fähig, kein Datenbankserver nötig |
| `python-dateutil` | 2.9.0 | Timestamp-Parsing beliebiger Formate | Robuster als `strptime` bei unbekannten oder inkonsistenten Log-Zeitformaten |
| `pytz` | 2024.1 | Zeitzonen-Datenbank | Vollständige IANA-Zeitzonen für UTC-Konvertierung |
| `reportlab` | 4.1.0 | Programmatische PDF-Generierung | Direkte Kontrolle über Layout und Inhalt ohne externe Office-Abhängigkeit |
| `timesketch-api-client` | 20240101 | Timesketch REST API | Offizieller Client für Timeline-Upload und Annotationen |
| `rich` | ≥ 13.0.0 | Terminal-UI mit Live-Fortschrittsanzeige | Strukturierte, lesbare Ausgabe für Forensiker während laufender Analyse |
| `tqdm` | ≥ 4.66.0 | Fortschrittsbalken für Dateioperationen | Ergänzung zu `rich` für einfache Iterationsfortschritte |
| `pyyaml` | 6.0.1 | YAML-Konfigurationsdatei parsen | Standard-Bibliothek für `config.yaml` |
| `requests` | 2.31.0 | HTTP-Kommunikation mit Timesketch | Abhängigkeit des Timesketch-Clients |

Zusätzlich zu den Python-Bibliotheken setzt die Pipeline auf **externe Kommandozeilen-Werkzeuge**, die auf dem Analysesystem installiert sein müssen und über Python-Subprozesse aufgerufen werden:

**Tabelle 4.3:** Externe Werkzeuge

| Werkzeug | Version | Verwendung in Stage |
|---|---|---|
| The Sleuth Kit (`fls`, `icat`, `mmls`, `tsk_recover`) | 4.12+ | Stage 05 |
| Volatility3 | 2.5.0 | Stage 02 |
| Hayabusa | ≥ 2.0 | Stage 06 (EVTX, optional) |
| `bulk_extractor` | ≥ 2.0 | Stage 07 (optional) |
| YARA | 4.3+ | Stage 09 |

The Sleuth Kit bildet das Fundament der Dateisystem-Extraktion: `mmls` liest die Partitionstabelle, `fls` listet alle Dateien und Verzeichniseinträge inklusive gelöschter Inodes, `icat` extrahiert einzelne Dateien anhand ihrer Inode-Nummer, und `tsk_recover` stellt Datei-Fragmente aus ungenutztem Datenträgerbereich wieder her. Hayabusa analysiert Windows Event Log-Dateien (EVTX) auf Basis von Sigma-Regeln und wird in Stage 06 bedingt eingesetzt, wenn EVTX-Dateien im Analysematerial vorhanden sind. `bulk_extractor` ergänzt die Regex-basierte IOC-Extraktion durch Carving-Methoden, die auch in unstrukturiertem Speicherbereich nach IOC-Mustern suchen.

### 4.4.2 Containerisierung (Docker)

Die Pipeline selbst läuft direkt auf dem Analyserechner als Python-Prozess ohne Containerisierung. Dies ist bewusst so gewählt: Die Pipeline benötigt direkten Zugriff auf lokale Dateipfade für Disk-Images (bis in den Terabyte-Bereich), auf externe Binaries wie TSK und Hayabusa sowie auf `/dev`-Geräte bei Live-Analysen. Eine vollständige Containerisierung würde diese Pfad-Abhängigkeiten erheblich verkomplizieren.

Containerisiert werden hingegen die optionalen Dienste für **Timesketch** (forensische Timeline-Visualisierung) und **Elasticsearch** (Suchindex für Timesketch). Die Datei `docker-compose.yml` definiert einen zweistufigen Stack:

- **Elasticsearch 7.17.9** läuft als Single-Node-Cluster (1 GB Heap-Memory, Port 9200) mit persistentem Volume `es_data`. Elasticsearch dient als Suchbackend für Timesketch.
- **Timesketch** (aktuellste stabile Version) stellt ein Web-Interface zur interaktiven forensischen Timeline-Analyse auf Port 5000 bereit. Analyseergebnisse werden im Volume `ts_data` gespeichert.

```yaml
# Auszug docker-compose.yml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    volumes:
      - es_data:/usr/share/elasticsearch/data
  timesketch:
    image: us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:latest
    ports:
      - "5000:5000"
    volumes:
      - ts_data:/var/lib/timesketch
```

Der Workflow für den Timesketch-Upload ist von der Pipeline getrennt: Nach Abschluss von Stage 14 steht die Datei `events.db` im Ausgabeordner zur Verfügung. Das separate Skript `upload_timesketch.py` liest diese Datenbank, konvertiert die Events in das JSONL-Format und lädt sie über die Timesketch-REST-API hoch. Timesketch ermöglicht es dem Forensiker anschließend, die Timeline interaktiv zu durchsuchen, zu filtern und zu annotieren. Optional können KI-gestützte Interpretationen über eine lokale Ollama-Instanz als Annotationen hinzugefügt werden.

Die Containerisierung von Timesketch und Elasticsearch sorgt für eine reproduzierbare, von der Systemumgebung unabhängige Betriebsumgebung dieser Dienste. Portabilitätsprobleme durch abweichende Elasticsearch-Versionen oder Python-Abhängigkeiten von Timesketch werden vollständig vermieden.

---

## 4.5 Designentscheidungen und Abwägungen

Dieses Unterkapitel dokumentiert die zentralen Designentscheidungen, die während der Konzeption und Implementierung der Pipeline getroffen wurden. Für jede Entscheidung werden das zugrunde liegende Problem, die betrachteten Alternativen, die gewählte Lösung und die Begründung dargelegt.

### Entscheidung 1: Modulare Stage-Architektur statt monolithischer Implementierung

**Problem:** Eine forensische Analyse-Pipeline umfasst viele konzeptuell unterschiedliche Verarbeitungsschritte: Dateierkennung, RAM-Analyse, Dateisystem-Extraktion, Log-Parsing, IOC-Extraktion, Normalisierung, Anti-Forensics-Erkennung und Report-Generierung. Eine monolithische Implementierung — alle Schritte in einer oder wenigen Dateien — wäre anfangs einfacher zu schreiben, würde aber die Wartbarkeit und Erweiterbarkeit schnell einschränken.

**Alternativen:**
- *Option A (monolithisch):* Alle Analyseschritte in `pipeline.py` als Funktionen. Einfacher Start, aber enge Kopplung: Änderung an einem Schritt kann andere brechen.
- *Option B (modular):* Jede Stage als eigenständiges Python-Modul mit einheitlicher `run(ctx)`-Schnittstelle.

**Entscheidung:** Option B — modulare Stage-Architektur.

**Begründung:** Die einheitliche `run(ctx: PipelineContext) -> PipelineContext`-Schnittstelle ermöglicht es, jede Stage isoliert zu entwickeln, zu testen und zu ersetzen. Das Hinzufügen einer neuen Analyse-Stage erfordert lediglich die Implementierung eines neuen Moduls und seine Einbindung in `pipeline.py` — alle anderen Stages bleiben unverändert. Das System ist damit offen für Erweiterung, aber geschlossen gegenüber Modifikation bestehender Komponenten. Für die Bachelorarbeit hatte diese Entscheidung zudem den Vorteil, dass die Pipeline schrittweise entwickelt und jede Stage einzeln getestet werden konnte.

---

### Entscheidung 2: Gemeinsames Datenobjekt (PipelineContext) statt Message Queue

**Problem:** Analysedaten müssen über alle Stages hinweg akkumuliert werden: Stage 01 setzt den Dateityp und Hash, Stage 03 ergänzt Betriebssystem und Zeitzone, Stage 06 schreibt den EventStore-Pfad, Stage 09 füllt die Anti-Forensics-Treffer. Alle nachgelagerten Stages müssen auf diese Informationen zugreifen.

**Alternativen:**
- *Option A (Message Queue):* Jede Stage veröffentlicht Ergebnisse in einer Queue (z. B. Redis, RabbitMQ). Nachfolge-Stages abonnieren relevante Nachrichten. Skalierbar für verteilte Systeme, aber Overhead durch Serialisierung und Infrastruktur.
- *Option B (Datenbankschema):* Alle Zwischenergebnisse werden in eine relationale Datenbank geschrieben. Flexibel, aber erfordert Schema-Design für heterogene Ergebnistypen.
- *Option C (gemeinsames Dataclass-Objekt):* Alle Stages lesen und schreiben in ein geteiltes `PipelineContext`-Objekt.

**Entscheidung:** Option C — gemeinsames `PipelineContext`-Dataclass-Objekt.

**Begründung:** Die Pipeline läuft ausschließlich sequenziell auf einem einzigen Rechner. Kein verteiltes System, keine Skalierung über mehrere Maschinen — damit entfällt der Hauptvorteil von Message Queues. Das `@dataclass`-Objekt ist direkt typsicher annotiert, ohne Umwege über Serialisierung/Deserialisierung introspektierbar und mit Python-Debuggern vollständig transparent. Ein Datenbankschema für heterogene Zwischenergebnisse (Listen von Objekten, verschachtelte Dicts, Pfadobjekte) wäre unnötig komplex. Die `@dataclass`-Deklaration mit `field(default_factory=...)` verhindert zudem geteilte Mutablen zwischen Instanzen und sorgt für sichere Standardwerte.

---

### Entscheidung 3: DuckDB statt In-Memory-Liste oder SQLite für Events

**Problem:** Stage 06 erzeugt je nach Image-Größe zwischen einigen tausend und mehreren Millionen normalisierter Log-Events. Eine Python-Liste `ctx.events = []` als primärer Datenspeicher wäre bei großen Datenmengen nicht praktikabel: 3 Millionen Events mit je 200 Byte Overhead bedeuten ~600 MB RAM-Verbrauch allein für den Event-Puffer, zusätzlich zum laufenden Python-Prozess. Stage 08 benötigt außerdem SQL-ähnliche `UPDATE`-Operationen für die Timestamp-Normalisierung.

**Alternativen:**
- *Option A (Python-Liste im RAM):* Einfachste Implementierung. Scheitert bei Images > 20 GB an RAM-Grenzen.
- *Option B (SQLite):* Weit verbreitet, keine Installation nötig. Begrenzte analytische Abfragemöglichkeiten; keine echten Column-Store-Vorteile.
- *Option C (DuckDB):* Eingebetteter In-Process Column-Store. SQL-fähig, kein Server nötig, effizienter für analytische Abfragen auf Zeitreihen.

**Entscheidung:** Option C — DuckDB über den `EventStore`.

**Begründung:** DuckDB kombiniert die Einfachheit von SQLite (keine Server-Installation, eingebettet im Python-Prozess) mit den analytischen Stärken eines Column-Stores. DuckDB wurde speziell für analytische Workloads entwickelt und eignet sich daher besonders für Aggregationen und Filteroperationen über große Datensätze — bei vergleichbar einfachem Deployment wie SQLite. Für die Pipeline ist insbesondere relevant: Stage 08 kann Timestamp-Normalisierung als SQL-`UPDATE` mit einer Python-UDF ausführen, ohne die gesamte Event-Tabelle in den Arbeitsspeicher zu laden. Stage 06 nutzt Batch-Inserts in 1.000er-Chunks, die DuckDB intern puffert. Der `EventStore` kapselt alle DuckDB-Zugriffe und kann bei Bedarf durch eine andere Datenbanklösung ersetzt werden, ohne die Stage-Module zu berühren.

---

### Entscheidung 4: Fehlertoleranz (Graceful Degradation) statt Fail-Fast

**Problem:** Die Pipeline ist von externen Werkzeugen abhängig (The Sleuth Kit, Volatility3, Hayabusa, bulk_extractor), die auf dem Zielsystem möglicherweise nicht installiert sind, eine abweichende Version haben oder bei einem bestimmten Image-Format fehlschlagen. Eine Fail-Fast-Strategie — Pipeline stoppt beim ersten Fehler — würde bedeuten, dass ein fehlendes RAM-Image alle nachgelagerten Log-Analysen verhindert.

**Alternativen:**
- *Option A (Fail-Fast):* Bei jedem Stage-Fehler wird die Pipeline abgebrochen. Klarer Fehlerzustand, aber partielles Ergebnis ist unmöglich.
- *Option B (Graceful Degradation):* Stage-Fehler werden gefangen und protokolliert; die Pipeline setzt mit der nächsten Stage fort.

**Entscheidung:** Option B — Graceful Degradation.

**Begründung:** In der forensischen Praxis ist ein partielles Analyseergebnis erheblich wertvoller als kein Ergebnis. Fehlt ein RAM-Dump, kann Stage 02 sicher übersprungen werden — alle Disk-Forensik-Stages liefern weiterhin Ergebnisse. Schlägt ein einzelner Log-Parser fehl, werden die anderen Parser nicht beeinträchtigt. Stage 13 bewertet am Ende des Durchlaufs die Gesamtqualität anhand der Fehler-Anzahl und gibt ein Urteil von „SEHR GUT" (0 Fehler) bis „KRITISCH" (≥ 4 Fehler) aus, das transparent im Report dokumentiert wird. Der Analyst erhält damit sowohl die verfügbaren Ergebnisse als auch eine ehrliche Einschätzung ihrer Vollständigkeit.

---

### Entscheidung 5: Zweistufige Konfiguration — config.yaml und CLI-Parameter

**Problem:** Die Pipeline muss in unterschiedlichen Einsatzszenarien betreibbar sein: in einer Laborumgebung mit Timesketch-Installation, auf einem Forensik-Laptop ohne Timesketch, mit vollem YARA-Regelwerk oder nur mit den zwei internen Pipeline-Regeln, mit einem Worker oder mit sechs parallelen Workern.

**Alternativen:**
- *Option A (alles in config.yaml):* Alle Parameter in der Konfigurationsdatei. Erfordert manuelle Änderung vor jedem Analyse-Lauf.
- *Option B (alles per CLI):* Keine persistente Konfiguration, alle Optionen per Kommandozeilenargument. Führt zu sehr langen Befehlen bei jeder Ausführung.
- *Option C (zweistufig):* Persistente Infrastrukturparameter in `config.yaml`, variable Ausführungsparameter per CLI.

**Entscheidung:** Option C — Zweistufige Konfiguration.

**Begründung:** `config.yaml` enthält Parameter, die sich selten ändern: Timesketch-Verbindungsdaten, Binärpfade externer Tools, ML-Schwellenwerte. Diese sind von der Analyseumgebung abhängig, nicht von der einzelnen Analyse. CLI-Parameter hingegen sind per Lauf variabel: `--yara custom` für einen Schnellscan, `--yara full` für eine vollständige Analyse, `--workers 6` auf einem leistungsfähigen Server, `--no-timesketch` auf einem Offline-Analyselaptop. Diese Trennung hält den Aufruf der Pipeline kurz und erlaubt gleichzeitig die persistente Konfiguration der Umgebung.

---

### Entscheidung 6: Chain of Custody als eigenständige Klasse

**Problem:** Forensische Berichte müssen den Analyseprozess nachvollziehbar dokumentieren. Die Chain of Custody (CoC) ist im forensischen Kontext ein zentrales Qualitätsmerkmal: Sie belegt, welche Verarbeitungsschritte in welcher Reihenfolge zu welchem Zeitpunkt ausgeführt wurden und ob dabei Fehler aufgetreten sind.

**Alternativen:**
- *Option A (Log-Datei):* Die CoC wird als einfache Textdatei ins `pipeline.log` geschrieben. Einfach, aber schwer maschinenlesbar und nicht als separates Dokument exportierbar.
- *Option B (Felder im PipelineContext):* CoC-Einträge als Liste im `PipelineContext` ohne eigene Klasse. Funktional, aber keine klare Trennung von Analysedaten und Protokolldaten.
- *Option C (eigenständige Klasse):* `ChainOfCustody` als eigene Datenklasse in `models/chain_of_custody.py` mit `CoCEntry`-Unterklasse und `add_entry()`-Methode.

**Entscheidung:** Option C — eigenständige `ChainOfCustody`-Klasse.

**Begründung:** Die Chain of Custody ist kein Nebenprodukt der Analyse, sondern ein eigenständiges Lieferobjekt. Stage 14 exportiert sie als separates PDF-Dokument, das unabhängig vom technischen Analysebericht an Auftraggeber, Anwälte oder Gerichte übergeben werden kann. Eine eigene Klasse macht die CoC-Logik testbar, klar abgegrenzt von den Analyseergebnissen und erweiterbar — etwa um digitale Signaturen oder Prüfsummen der CoC-Einträge selbst. Die Implementierung als `@dataclass` erlaubt die direkte Serialisierung in JSON, was für zukünftige Erweiterungen (z. B. Integration in forensische Case-Management-Systeme) relevant ist.

