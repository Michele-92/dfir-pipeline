import logging
import re
from pathlib import Path
from typing import List, Dict

from tqdm import tqdm
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

TIMESTOMPING_KEYWORDS = ['timestomp', 'touch -t', 'setfiletime', '$si', '$fn']
# Review-Fix HIGH #17: '> /dev/null 2>&1' entfernt — Standard-Redirect in
# praktisch jedem Cronjob, erzeugte massenhaft CRITICAL-False-Positives.
# Echtes Log-Wiping wird ueber die /var/log-Patterns weiter erkannt.
LOG_WIPE_KEYWORDS     = ['> /var/log', 'truncate -s 0', 'rm -f /var/log',
                          'echo "" > /var/log', 'shred /var/log']
# Review-Fix HIGH #17: insmod/modprobe sind bei jedem Boot normal —
# nur noch verdaechtig, wenn aus Shell-History/auth.log (Benutzer-Kommando)
# oder mit Modul-Pfad in Staging-Verzeichnissen.
ROOTKIT_KEYWORDS      = ['ld_preload', '/proc/kcore', 'sys_call_table']
ROOTKIT_CTX_KEYWORDS  = ['insmod', 'modprobe', 'ptrace']
ROOTKIT_CTX_SOURCES   = ('bash_history', 'zsh_history', 'fish_history', 'auth')
ROOTKIT_CTX_PATHS     = ['/tmp/', '/var/tmp/', '/dev/shm/', '/home/']
ADS_PATTERN           = re.compile(r'\w+:\w+')  # NTFS ADS: file:stream
SECURE_DELETE_TOOLS   = ['shred', 'srm', 'wipe', 'bleachbit', 'dd if=/dev/zero',
                          'dd if=/dev/urandom']

# ── Anti-Forensik-Konstanten (neu) ───────────────────────────────────────────

# Log-Dateien die auf /dev/null zeigen könnten (Multi-OS: auth.log + secure etc.)
DEVNULL_LOG_TARGETS = [
    'var/log/auth.log', 'var/log/syslog', 'var/log/kern.log',
    'var/log/daemon.log', 'var/log/ufw.log', 'var/log/rinetd.log',
    'var/log/secure', 'var/log/messages',           # RHEL
    'var/log/wtmp', 'var/log/btmp', 'var/log/lastlog', 'var/log/journal',
    'root/.bash_history', 'root/.zsh_history',      # Shell-Histories
]

# rc.local Patterns die auf Anti-Forensik hinweisen
RC_LOCAL_SUSPICIOUS = [
    (r'ln\s+-s\s+/dev/null',        'Symlink auf /dev/null erstellt'),
    (r'>\s*/var/log',               'Log-Datei geleert (Output-Redirect)'),
    (r'rm\s+(-rf?\s+)?/var/log',    'Log-Datei geloescht'),
    (r'truncate\s+-s\s+0',          'Log-Datei geleert (truncate)'),
    (r'shred\s+.*(/var/log|log)',   'Log-Datei sicher geloescht'),
    (r'systemctl\s+stop\s+\S*log',  'Log-Service gestoppt'),
    (r'kill.*syslog|kill.*rsyslog', 'Syslog-Prozess beendet'),
    (r'journalctl.*vacuum',         'Journal bereinigt (vacuum)'),
]

# ExecStop Wiping-Tools in systemd-Services
EXECSTOP_WIPING_TOOLS = ['sdmem', 'secure-delete', 'wipe', 'srm', 'shred', 'bleachbit']

# Desktop-Indikatoren fuer Swap-Anomalie-Heuristik
DESKTOP_HINTS = ['xorg', 'xserver', 'gnome', 'kde', 'xfce', 'gdm', 'lightdm', 'sddm', 'display-manager']


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 9: Anti-Forensics-Erkennung')
    hits: List[Dict] = []

    hits += _check_timestomping(ctx)
    hits += _check_log_wiping(ctx)
    hits += _check_rootkit_indicators(ctx)
    hits += _check_secure_delete(ctx)
    hits += _check_yara(ctx)
    # ── Neue Anti-Forensik-Checks (Stage-03-Daten) ────────────────────────
    hits += _check_devnull_symlinks(ctx)
    hits += _check_rc_local_antiforensics(ctx)
    hits += _check_grub_memory_params(ctx)
    hits += _check_kernel_compile_flags_check(ctx)
    hits += _check_execstop_wiping(ctx)
    hits += _check_swap_anomaly(ctx)
    hits += _check_kernel_discrepancy(ctx)
    hits += _check_journal_wtmp_consistency(ctx)

    ctx.antiforensics_hits = hits
    log.info(f'  {len(hits)} Anti-Forensics-Treffer gefunden')
    if ctx.coc:
        ctx.coc.add_entry('stage_09', f'Anti-Forensics: {len(hits)} Treffer')
    return ctx


def _check_timestomping(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in tqdm(ctx.normalized_events, desc='  Timestomping-Scan', unit='Event', leave=False, dynamic_ncols=True):
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in TIMESTOMPING_KEYWORDS):
            hits.append({
                'type':     'timestomping',
                'file':     event.file_path or 'unbekannt',
                'details':  event.message[:200],
                'severity': 'high',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    return hits


def _check_log_wiping(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in tqdm(ctx.normalized_events, desc='  Log-Wiping-Scan', unit='Event', leave=False, dynamic_ncols=True):
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in LOG_WIPE_KEYWORDS):
            hits.append({
                'type':     'log_deletion',
                'file':     event.file_path or '/var/log/*',
                'details':  event.message[:200],
                'severity': 'critical',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    for key, lines in ctx.disk_artifacts.items():
        for line in lines:
            if any(kw in line.lower() for kw in LOG_WIPE_KEYWORDS):
                hits.append({
                    'type':     'log_deletion',
                    'file':     line.strip()[:100],
                    'details':  f'Dissect-Fund: {line[:100]}',
                    'severity': 'high',
                    'source':   f'dissect:{key}',
                    'timestamp':'',
                })
    return hits


def _check_rootkit_indicators(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in tqdm(ctx.normalized_events, desc='  Rootkit-Scan', unit='Event', leave=False, dynamic_ncols=True):
        msg_lower = event.message.lower()
        suspicious = any(kw in msg_lower for kw in ROOTKIT_KEYWORDS)
        if not suspicious and any(kw in msg_lower for kw in ROOTKIT_CTX_KEYWORDS):
            # Kontext-Pruefung: Benutzer-Kommando oder Staging-Pfad?
            suspicious = (event.source in ROOTKIT_CTX_SOURCES
                          or any(p in msg_lower for p in ROOTKIT_CTX_PATHS))
        if suspicious:
            hits.append({
                'type':     'rootkit_indicator',
                'file':     event.file_path or 'unbekannt',
                'details':  event.message[:200],
                'severity': 'critical',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    for plugin, rows in ctx.memory_results.items():
        for row in rows:
            row_str = str(row).lower()
            if 'hidden' in row_str or 'injected' in row_str or 'malfind' in plugin:
                hits.append({
                    'type':     'rootkit_indicator',
                    'file':     str(row)[:80],
                    'details':  f'Volatility {plugin}: {str(row)[:150]}',
                    'severity': 'critical',
                    'source':   f'volatility:{plugin}',
                    'timestamp':'',
                })
    return hits


def _check_secure_delete(ctx: PipelineContext) -> List[Dict]:
    hits = []
    for event in tqdm(ctx.normalized_events, desc='  Secure-Delete-Scan', unit='Event', leave=False, dynamic_ncols=True):
        msg_lower = event.message.lower()
        if any(kw in msg_lower for kw in SECURE_DELETE_TOOLS):
            hits.append({
                'type':     'secure_delete',
                'file':     event.file_path or 'unbekannt',
                'details':  event.message[:200],
                'severity': 'high',
                'source':   event.source,
                'timestamp':event.timestamp.isoformat(),
            })
    return hits


def _get_yara_rules_dir(yara_mode: str) -> Path:
    base = Path(__file__).parent.parent / 'data' / 'yara-rules'
    if yara_mode == 'linux': return base / 'linux'
    if yara_mode == 'full':  return base
    return base / 'custom'


def _check_yara(ctx: PipelineContext) -> List[Dict]:
    hits = []
    rules_dir = _get_yara_rules_dir(ctx.yara_mode)
    log.info(f'  YARA-Modus: {ctx.yara_mode} → {rules_dir}')
    if not rules_dir.exists():
        log.warning(f'  YARA-Regelordner nicht gefunden: {rules_dir}')
        return hits
    try:
        import yara
        rule_files = list(rules_dir.rglob('*.yar'))
        if not rule_files:
            return hits

        case_dir = ctx.case_dir
        if not case_dir or not case_dir.exists():
            return hits

        targets = [t for t in case_dir.rglob('*')
                   if t.is_file() and t.stat().st_size <= 50_000_000]

        for rf in rule_files:
            try:
                rule_set = yara.compile(filepath=str(rf))
                for target in targets:
                    try:
                        matches = rule_set.match(str(target), timeout=30)
                        for match in matches:
                            hits.append({
                                'type':     'yara_match',
                                'file':     str(target),
                                'details':  f'YARA-Regel: {match.rule} Tags: {match.tags}',
                                'severity': 'high',
                                'source':   'yara',
                                'timestamp':'',
                                'rule':     match.rule,
                            })
                    except Exception:
                        continue
                del rule_set
            except Exception:
                continue
    except ImportError:
        log.warning('yara-python nicht installiert — YARA-Scan übersprungen')
    return hits


# ── Neue Anti-Forensik-Checks ─────────────────────────────────────────────────

def _check_devnull_symlinks(ctx: PipelineContext) -> List[Dict]:
    """Prueft ob Log-Dateien oder Shell-Histories via Symlink auf /dev/null zeigen.
    Methode: primary_symlinks aus Stage 03 (fls l/l Eintraege + icat Ziel).
    Multi-OS: prueft Debian-Pfade (auth.log, syslog) UND RHEL-Pfade (secure, messages)."""
    hits = []
    symlinks = getattr(ctx, 'primary_symlinks', {})
    for log_path in DEVNULL_LOG_TARGETS:
        target = symlinks.get(log_path, '')
        if '/dev/null' in target:
            hits.append({
                'type':      'devnull_symlink',
                'file':      log_path,
                'details':   f'Symlink auf /dev/null: {log_path} → {target} '
                             f'— keinerlei Protokollierung dieser Datei',
                'severity':  'critical',
                'source':    'fls_symlink_scan',
                'timestamp': '',
            })
    return hits


def _check_rc_local_antiforensics(ctx: PipelineContext) -> List[Dict]:
    """Analysiert rc.local auf Anti-Forensik-Kommandos beim Systemstart.
    Quelle: ctx.rc_local_content (Stage 03 — auch Alpine local.d/*.start).
    Prueft auf: /dev/null Symlinks, Log-Loeschung, Service-Stopp, Journal-Vacuum."""
    hits = []
    content = getattr(ctx, 'rc_local_content', '')
    if not content:
        return hits
    for pattern, desc in RC_LOCAL_SUSPICIOUS:
        for line in content.splitlines():
            if line.strip().startswith('#'):
                continue
            if re.search(pattern, line, re.IGNORECASE):
                hits.append({
                    'type':      'rc_local_antiforensics',
                    'file':      '/etc/rc.local',
                    'details':   f'{desc}: {line.strip()[:150]}',
                    'severity':  'critical',
                    'source':    'rc_local',
                    'timestamp': '',
                })
                break  # pro Pattern einmal melden
    return hits


def _check_grub_memory_params(ctx: PipelineContext) -> List[Dict]:
    """Bewertet GRUB-Boot-Parameter auf Memory-Wiping-Indikatoren.
    Quelle: ctx.grub_config['antiforensic_params'] (Stage 03).
    Relevant: init_on_free=1 (RAM-Seiten sofort nullen), page_poison=1 (0xAA-Fuellen)."""
    hits = []
    grub = getattr(ctx, 'grub_config', {})
    for param in grub.get('antiforensic_params', []):
        hits.append({
            'type':      'grub_memory_wipe',
            'file':      'etc/default/grub / boot/grub/grub.cfg',
            'details':   f'Boot-Parameter aktiv: {param} — RAM-Bereinigung bei '
                         f'Prozessfreigabe, post-mortem Rekonstruktion erschwert',
            'severity':  'critical',
            'source':    'grub_config',
            'timestamp': '',
        })
    return hits


def _check_kernel_compile_flags_check(ctx: PipelineContext) -> List[Dict]:
    """Bewertet einkompilierte Kernel-Flags auf Anti-Forensik.
    Quelle: ctx.kernel_compile_flags (Stage 03, aus /boot/config-<kernel>).
    Gleich fuer alle Distros — Pfad und Flag-Namen sind kernel-level Standard."""
    hits = []
    flags_map = getattr(ctx, 'kernel_compile_flags', {})
    for kernel, info in flags_map.items():
        for flag in info.get('active_flags', []):
            hits.append({
                'type':      'kernel_compile_antiforensics',
                'file':      f'boot/config-{kernel}',
                'details':   f'Einkompiliertes Anti-Forensik-Flag: {flag} '
                             f'(Kernel: {kernel}) — Speicher wird nativ ueberschrieben',
                'severity':  'high',
                'source':    'kernel_config',
                'timestamp': '',
            })
    return hits


def _check_execstop_wiping(ctx: PipelineContext) -> List[Dict]:
    """Scannt systemd .service-Dateien auf ExecStop-Direktiven mit Wiping-Tools.
    Multi-OS: systemd (Debian/RHEL/Arch) und OpenRC init.d (Alpine).
    Entspricht analyze_systemd_services() des Betreuer-Scripts, aber via TSK/icat."""
    hits = []
    profiles = getattr(ctx, 'partition_profiles', [])
    primary  = next((p for p in profiles if p.get('is_primary')), None)
    if not primary or not ctx.disk_image_path:
        return hits
    offset = primary.get('offset', 0)

    try:
        from stages.stage03_profiling import _index_partition, _read_icat as _ricat
        index = _index_partition(ctx.disk_image_path, offset)

        # systemd: Debian/RHEL/Arch
        service_paths = [
            p for p in index
            if p.endswith('.service') and any(
                d in p for d in ('etc/systemd/system', 'lib/systemd/system',
                                 'usr/lib/systemd/system')
            )
        ]
        for svc_path in service_paths:
            content = _ricat(ctx.disk_image_path, offset, index[svc_path])
            if 'ExecStop' not in content:
                continue
            for tool in EXECSTOP_WIPING_TOOLS:
                m = re.search(r'ExecStop=.*' + re.escape(tool), content, re.IGNORECASE)
                if m:
                    svc_name = svc_path.split('/')[-1]
                    hits.append({
                        'type':      'execstop_wiping',
                        'file':      svc_path,
                        'details':   f'ExecStop mit Wiping-Tool "{tool}" in {svc_name}: '
                                     f'{m.group()[:120]}',
                        'severity':  'critical',
                        'source':    'systemd_services',
                        'timestamp': '',
                    })

        # OpenRC (Alpine): /etc/init.d/* Scripts
        os_family = getattr(ctx, 'os_family', '')
        if os_family == 'alpine':
            init_paths = [p for p in index if p.startswith('etc/init.d/')]
            for init_path in init_paths:
                content = _ricat(ctx.disk_image_path, offset, index[init_path])
                for tool in EXECSTOP_WIPING_TOOLS:
                    if re.search(re.escape(tool), content, re.IGNORECASE):
                        hits.append({
                            'type':      'execstop_wiping',
                            'file':      init_path,
                            'details':   f'OpenRC init.d Script mit Wiping-Tool "{tool}": '
                                         f'{init_path.split("/")[-1]}',
                            'severity':  'high',
                            'source':    'openrc_init',
                            'timestamp': '',
                        })
    except Exception as e:
        log.warning(f'_check_execstop_wiping fehlgeschlagen: {e}')
    return hits


def _check_swap_anomaly(ctx: PipelineContext) -> List[Dict]:
    """Meldet fehlende Swap-Konfiguration als potenzielle Anti-Forensik.
    Server ohne Swap = normal (kein False Positive).
    Desktop ohne Swap = verdaechtig — Heuristik via installierte Pakete."""
    hits = []
    swap = getattr(ctx, 'swap_config', {})
    if swap.get('found'):
        return hits
    profiles = getattr(ctx, 'partition_profiles', [])
    primary  = next((p for p in profiles if p.get('is_primary')), None)
    if not primary:
        return hits
    pkgs    = primary.get('packages', {})
    notable = ' '.join(p.lower() for p in pkgs.get('notable', []))
    svcs    = ' '.join(primary.get('services', {}).get('enabled', []))
    if any(h in notable or h in svcs for h in DESKTOP_HINTS):
        hits.append({
            'type':      'swap_missing',
            'file':      'etc/fstab',
            'details':   'Kein Swap konfiguriert auf potenziellem Desktop-System — '
                         'RAM-Forensik aus Swap-Partition nicht moeglich',
            'severity':  'medium',
            'source':    'fstab',
            'timestamp': '',
        })
    return hits


def _check_kernel_discrepancy(ctx: PipelineContext) -> List[Dict]:
    """Vergleicht konfigurierten GRUB-Kernel mit tatsaechlich geladenem Kernel.
    Entspricht analyze_system_state() des Betreuer-Scripts.
    Reboot-Flag zuverlässig nur auf Debian — Diskrepanz wird fuer alle OS gemeldet."""
    hits = []
    grub           = getattr(ctx, 'grub_config', {})
    active_kernel  = grub.get('active_kernel', '')
    loaded_kernel  = getattr(ctx, 'loaded_kernel_from_logs', '')
    reboot_pending = getattr(ctx, 'reboot_pending', False)

    if reboot_pending:
        hits.append({
            'type':      'pending_reboot',
            'file':      'var/run/reboot-required',
            'details':   f'Ausstehender Neustart — Kernel-Update installiert aber nicht aktiv. '
                         f'GRUB-Default: {active_kernel or "?"} | '
                         f'Geladen: {loaded_kernel or "?"}',
            'severity':  'medium',
            'source':    'reboot_required',
            'timestamp': '',
        })

    if active_kernel and loaded_kernel and active_kernel != loaded_kernel:
        hits.append({
            'type':      'kernel_discrepancy',
            'file':      'boot/grub/grub.cfg',
            'details':   f'Kernel-Diskrepanz: GRUB-Default="{active_kernel}" '
                         f'aber tatsaechlich geladen="{loaded_kernel}" — '
                         f'System lief auf altem Kernel',
            'severity':  'high',
            'source':    'grub_vs_logs',
            'timestamp': '',
        })
    return hits


def _check_journal_wtmp_consistency(ctx: PipelineContext) -> List[Dict]:
    """Vergleicht Login-Ereignisse aus Journal-Events mit wtmp-Login-Methoden.
    Starke Diskrepanz deutet auf Log-Manipulation hin.
    Schwellwert: 0 Journal-Logins bei wtmp-Eintraegen = kritisch, 5x-Faktor = medium."""
    hits = []
    journal_logins = sum(
        1 for e in ctx.normalized_events
        if 'session opened' in e.message.lower() or 'accepted' in e.message.lower()
    )
    profiles = getattr(ctx, 'partition_profiles', [])
    primary  = next((p for p in profiles if p.get('is_primary')), None)
    wtmp_logins = 0
    if primary:
        for u in primary.get('users', []):
            wtmp_logins += len(u.get('login_methods', []))

    if wtmp_logins > 0 and journal_logins == 0:
        hits.append({
            'type':      'journal_wtmp_mismatch',
            'file':      'var/log/wtmp vs var/log/journal',
            'details':   f'wtmp zeigt {wtmp_logins} Login-Methoden, '
                         f'aber 0 Session-Events in Log-Dateien — '
                         f'moeglich: Logs manipuliert oder geloescht',
            'severity':  'high',
            'source':    'wtmp_vs_journal',
            'timestamp': '',
        })
    elif wtmp_logins > 0 and journal_logins > 0:
        ratio = wtmp_logins / max(journal_logins, 1)
        if ratio > 5:
            hits.append({
                'type':      'journal_wtmp_mismatch',
                'file':      'var/log/wtmp vs var/log/journal',
                'details':   f'Starke Diskrepanz: wtmp={wtmp_logins} Logins, '
                             f'Journal={journal_logins} Session-Events '
                             f'(Faktor {ratio:.1f}x) — moegl. partielle Log-Manipulation',
                'severity':  'medium',
                'source':    'wtmp_vs_journal',
                'timestamp': '',
            })
    return hits
