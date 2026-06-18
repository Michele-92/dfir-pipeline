"""Stage 8.6 — Konsistenzpruefung (Event-Korroboration).

Laeuft NACH Stage 8 (Normalisierung), wenn die events.db vollstaendig
gefuellt ist. Ergaenzt Stage 3.5 (Basic Checks), die VOR Stage 6 laeuft und
nur die Extraktion pruefen kann — ohne die geparsten Events zu kennen.

Diese Stage nutzt die echten Events und prueft zwei Dinge, die Stage 3.5
strukturell nicht kann:

  C1  Paket-Korroboration:
      Stage 3.5 markiert "Log ohne Installation" nur per Dateinamen-Heuristik.
      Hier wird mit echten dpkg/apt/yum-Installations-Events gegengeprueft:
      - kein Installations-Event fuer das Paket  -> Anomalie BESTAETIGT
      - Installations-Event vorhanden            -> Stage-3.5-Fehlalarm entschaerft

  C2  Leeres/manipuliertes Log:
      Ein Log, das extrahiert wurde (in Stage 3.5 als vorhanden gemeldet),
      aber zu dem KEIN einziges Event geparst wurde (kein orig_path-Treffer in
      der events.db). Das deutet auf ein geleertes oder manipuliertes Log hin
      und ist forensisch relevant.

Jeder Befund traegt die nachpruefbare Quelle (Originalpfad auf dem Image,
Image-Label im Fall-Modus). Stage 3.5 bleibt unveraendert.
"""

import logging
from models.pipeline_context import PipelineContext
from utils.event_store import EventStore

log = logging.getLogger(__name__)

# Quellen, die Paket-Installationen melden (Parser-name == event.source)
_PKG_INSTALL_SOURCES = ('dpkg', 'apt', 'yum', 'dnf', 'pacman')


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 8.6: Konsistenzpruefung (Event-Korroboration)')

    ctx.consistency_checks    = []
    ctx.consistency_anomalies = 0

    db_path = getattr(ctx, 'events_db_path', None)
    if not db_path or not db_path.exists():
        log.warning('  Keine events.db — Stage 8.6 uebersprungen')
        ctx.stage_status['stage_08_6'] = 'UEBERSPRUNGEN — keine events.db'
        return ctx

    # ── Event-Aggregate einmal aus der DB ziehen ─────────────────────────────
    try:
        orig_counts, install_msgs = _load_aggregates(db_path)
    except Exception as e:
        log.warning(f'  events.db-Abfrage fehlgeschlagen: {e} — Stage 8.6 uebersprungen')
        ctx.stage_status['stage_08_6'] = f'UEBERSPRUNGEN — DB-Fehler: {e}'
        return ctx

    # ── Pro Image die Basic-Checks aus Stage 3.5 holen ───────────────────────
    #   Fall-Modus: je Image in ctx.evidence_items;  Einzel-Image: ctx.basic_checks
    if getattr(ctx, 'combined_case', False) and getattr(ctx, 'evidence_items', None):
        image_checks = [(ev.get('name', ''), ev.get('basic_checks') or [])
                        for ev in ctx.evidence_items]
    else:
        image_checks = [(getattr(ctx, 'evidence_label', '') or '',
                         getattr(ctx, 'basic_checks', []) or [])]

    checks = []
    for image_label, basic_checks in image_checks:
        if not basic_checks:
            continue
        # Installierte Pakete aus echten Events dieses Images
        installed = _installed_packages(install_msgs, image_label)

        for bc in basic_checks:
            if not bc.get('found'):
                continue  # nicht vorhandenes Log: betrifft Stage 3.5, nicht uns
            log_path = bc.get('log_path', '')
            service  = bc.get('service', '?')
            n_events = _events_for_path(orig_counts, log_path, image_label)

            # ── C2: Datei vorhanden, aber 0 Events geparst ───────────────────
            if n_events == 0:
                mandatory = bool(bc.get('expected'))
                sev = 'high' if mandatory else 'medium'
                checks.append(_chk(
                    'leeres_log', image_label, service, log_path,
                    'Datei extrahiert, aber 0 Events geparst — moeglich geleert/manipuliert',
                    severity=sev, anomaly=True))
                continue

            # ── C1: Paket-Korroboration bei "Log ohne Installation" ──────────
            if bc.get('anomaly_type') == 'log_without_install':
                pkg = service.split('(')[0].strip()
                if _pkg_in(pkg, installed):
                    checks.append(_chk(
                        'paket_korroboration', image_label, service, log_path,
                        f'Stage-3.5-Verdacht entschaerft: Installation von "{pkg}" '
                        f'durch Paket-Event belegt',
                        severity='info', anomaly=False))
                else:
                    checks.append(_chk(
                        'log_ohne_installation', image_label, service, log_path,
                        f'BESTAETIGT: Log vorhanden ({n_events} Events), aber kein '
                        f'Installations-Event fuer "{pkg}" — moeglich nachtraeglich platziert',
                        severity='high', anomaly=True))

    ctx.consistency_checks    = checks
    ctx.consistency_anomalies = sum(1 for c in checks if c['anomaly'])

    log.info(f'  Konsistenzpruefung: {len(checks)} Pruefungen, '
             f'{ctx.consistency_anomalies} Anomalien')
    ctx.stage_status['stage_08_6'] = f'{ctx.consistency_anomalies} Anomalien'
    if ctx.coc:
        ctx.coc.add_entry('stage_08_6',
                          f'Konsistenzpruefung: {ctx.consistency_anomalies} Anomalien')
    return ctx


# ─────────────────────────────────────────────────────────────────────────────
# Helfer
# ─────────────────────────────────────────────────────────────────────────────
def _load_aggregates(db_path):
    """Liest zwei Aggregate aus der events.db:
       orig_counts : {(evidence, orig_path_lower): event_count}
       install_msgs: Liste (evidence, message_lower) der Paket-Install-Events.
    """
    orig_counts = {}
    install_msgs = []
    with EventStore(db_path) as store:
        conn = store._conn
        for ev, op, cnt in conn.execute(
                "SELECT COALESCE(evidence,''), COALESCE(orig_path,''), COUNT(*) "
                "FROM events GROUP BY evidence, orig_path").fetchall():
            if op:
                orig_counts[(ev, op.lower())] = cnt
        placeholders = ','.join('?' * len(_PKG_INSTALL_SOURCES))
        for ev, msg in conn.execute(
                f"SELECT COALESCE(evidence,''), COALESCE(message,'') "
                f"FROM events WHERE source IN ({placeholders})",
                list(_PKG_INSTALL_SOURCES)).fetchall():
            if msg:
                install_msgs.append((ev, msg.lower()))
    return orig_counts, install_msgs


def _installed_packages(install_msgs, image_label):
    """Sammelt die Install-Meldungstexte des Images zu einem Suchkorpus."""
    out = []
    for ev, msg in install_msgs:
        if image_label and ev and ev != image_label:
            continue
        out.append(msg)
    return out


def _pkg_in(pkg, install_corpus):
    """Kommt das Paket in einem Installations-Event vor?"""
    if not pkg:
        return False
    p = pkg.lower()
    return any(p in msg for msg in install_corpus)


def _events_for_path(orig_counts, log_path, image_label):
    """Zaehlt Events, deren orig_path zum erwarteten Log passt.

    Pfad-Match wie in Stage 3.5: exakt, Verzeichnis-Praefix oder rotierte
    Variante (.1, .2.gz). Im Fall-Modus nur Events mit passendem Image-Label.
    """
    needle = '/' + log_path.strip('/').lower()
    total = 0
    for (ev, op), cnt in orig_counts.items():
        if image_label and ev and ev != image_label:
            continue
        opn = op if op.startswith('/') else '/' + op
        if opn == needle or opn.startswith(needle + '/') or opn.startswith(needle + '.'):
            total += cnt
    return total


def _chk(check_type, image, service, source_path, detail, severity, anomaly):
    return {
        'check':       check_type,
        'image':       image,
        'service':     service,
        'source_path': source_path,   # nachpruefbarer Originalpfad
        'detail':      detail,
        'severity':    severity,
        'anomaly':     anomaly,
    }
