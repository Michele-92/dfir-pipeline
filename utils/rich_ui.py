import re
import time
import threading
from typing import Dict, Optional

PRIVATE_IPS = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255\.255\.255)'
)

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

STAGE_INFO = {
    'stage_01':     ('01',     'Dateierkennung & Beweissicherung'),
    'stage_02_mem': ('02_mem', 'RAM-Analyse (Volatility3)'),
    'stage_02':     ('02',     'Partition-Layout'),
    'stage_03':   ('03',    'System-Profiling'),
    'stage_05':   ('05',    'Disk-Forensik'),
    'stage_03_5': ('03.5',  'Basic Checks'),
    'stage_06':   ('06',    'Log-Parsing (38 Parser)'),
    'stage_07':   ('07',    'IOC-Extraktion'),
    'stage_08':   ('08',    'Datennormalisierung'),
    'stage_09':   ('09',    'Anti-Forensics-Erkennung'),
    'stage_8.5':  ('8.5',  'Forensische Timeline-Analyse'),
    'stage_13':   ('13',    'Qualitätsprüfung'),
    'stage_14':   ('14',    'Export & Archivierung'),
}

SPINNERS = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']


class _StageState:
    def __init__(self):
        self.status     = 'waiting'   # waiting | running | ok | skipped | error
        self.start_time: Optional[float] = None
        self.duration:   Optional[float] = None
        self.note:       str = ''


class PipelineUI:
    def __init__(self, image_name: str):
        self.image_name    = image_name
        self.states: Dict[str, _StageState] = {k: _StageState() for k in STAGE_INFO}
        self.message       = ''
        self._live:        Optional[Live] = None
        self._spin_idx     = 0
        self._start        = time.time()
        self._timer_thread: Optional[threading.Thread] = None
        self._running      = False

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=8,
            redirect_stderr=True,
            redirect_stdout=True,
        )
        self._live.start()
        self._running = True
        self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
        self._timer_thread.start()

    def _timer_loop(self) -> None:
        while self._running:
            self._refresh()
            time.sleep(1)

    def stop(self) -> None:
        self._running = False
        if self._live:
            self._live.update(self._render())
            self._live.stop()

    def stage_start(self, key: str) -> None:
        if key in self.states:
            s = self.states[key]
            s.status     = 'running'
            s.start_time = time.time()
            self._refresh()

    def stage_done(self, key: str, status: str = 'ok', note: str = '') -> None:
        if key in self.states:
            s = self.states[key]
            s.status   = status
            s.duration = time.time() - (s.start_time or time.time())
            s.note     = note
            self.message = ''
            self._refresh()

    def set_message(self, msg: str) -> None:
        self.message = msg
        self._refresh()

    def show_summary(self, ctx) -> None:
        from stages.stage13_quality import evaluate_quality

        total     = time.time() - self._start
        total_str = _fmt_time(total)
        quality   = evaluate_quality(ctx)
        q_style   = {
            'SEHR GUT':     'bold green',
            'GUT':          'bold yellow',
            'EINGESCHRÄNKT':'bold orange3',
            'KRITISCH':     'bold red',
        }.get(quality, 'white')

        t = Table(box=box.ROUNDED, show_header=False,
                  border_style='bright_blue', expand=True)
        t.add_column('K', style='dim', width=22)
        t.add_column('V', style='bold white')

        t.add_row('Gesamtdauer',     total_str)
        t.add_row('Qualität',        Text(quality, style=q_style))
        t.add_row('Events',          f'{ctx.parsed_events:,}')
        t.add_row('IOCs',            str(len(ctx.iocs)))
        t.add_row('Anomalien',       str(len(ctx.anomalies)))
        t.add_row('MITRE-Techniken', str(len(ctx.mitre_hits)))
        t.add_row('Anti-Forensics',  str(len(ctx.antiforensics_hits)))
        if ctx.antiforensics_hits:
            t.add_row('[bold red]⚠ Warnung[/bold red]',
                      f'[red]{len(ctx.antiforensics_hits)} Anti-Forensics-Techniken erkannt![/red]')
        if ctx.case_dir:
            t.add_row('Ausgabe', str(ctx.case_dir))

        console.print(Panel(
            t,
            title='[bold green]✅  ANALYSE ABGESCHLOSSEN[/bold green]',
            border_style='green',
            padding=(0, 1),
        ))

        # ── Stage-Übersicht ───────────────────────────────────────────────────
        st = Table(box=box.SIMPLE, show_header=True, expand=True)
        st.add_column('Stage',        style='bold',  width=10)
        st.add_column('Beschreibung', min_width=32)
        st.add_column('Status',       width=14)
        st.add_column('Dauer',        width=7,  justify='right')
        st.add_column('Info',         style='dim')

        for key, (num, desc) in STAGE_INFO.items():
            state = self.states.get(key)
            if not state or state.status == 'waiting':
                continue
            if state.status == 'ok':
                icon, s_text = '✅', Text('OK',            style='green')
            elif state.status == 'skipped':
                icon, s_text = '⏭', Text('ÜBERSPRUNGEN',  style='dim')
            elif state.status == 'error':
                icon, s_text = '❌', Text('FEHLER',        style='bold red')
            else:
                icon, s_text = '⏳', Text(state.status,   style='yellow')

            dur  = _fmt_time(state.duration) if state.duration else '—'
            err  = ctx.stage_errors.get(key, '')
            info = err[:60] if err else state.note[:60]
            st.add_row(f'{icon}  {num}', desc, s_text, dur, info)

        console.print(Panel(
            st,
            title='[bold blue]Stage-Übersicht[/bold blue]',
            border_style='bright_blue',
            padding=(0, 1),
        ))

    def show_stage01_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        t.add_row('Dateiname',  ctx.disk_image_path.name if ctx.disk_image_path else '?')
        t.add_row('Format',     ctx.file_type or '?')
        compressed = getattr(ctx, 'file_size_compressed_gb', 0.0)
        if compressed and compressed > 0.0:
            t.add_row('Größe (E01-Datei)',    f'{compressed:.2f} GB  [dim](komprimiert auf Datenträger)[/dim]')
            t.add_row('Größe (Disk-Image)',   f'{ctx.file_size_gb:.2f} GB  [dim](logisch / unkomprimiert)[/dim]')
        else:
            t.add_row('Größe',      f'{ctx.file_size_gb:.2f} GB')
        # Review-Fix #19: Hashes vollstaendig anzeigen — keine Kuerzung
        if getattr(ctx, 'sha1', ''):
            t.add_row('SHA1 (E01)', ctx.sha1)
        if ctx.sha256:
            t.add_row('SHA256',  ctx.sha256)
        t.add_row('MD5',        ctx.md5 if ctx.md5 else '?')
        hash_src = getattr(ctx, 'hash_source', 'Berechnet')
        hash_style = 'green' if hash_src == 'E01-eingebettet' else 'dim'
        t.add_row('Hash-Quelle', Text(f'✅ {hash_src}' if hash_src == 'E01-eingebettet' else hash_src, style=hash_style))
        if ctx.coc:
            t.add_row('Analyse-Protokoll', ctx.coc.start_time.strftime('%Y-%m-%d %H:%M:%S UTC'))
        if ctx.case_dir:
            t.add_row('Case-Ordner', str(ctx.case_dir))
        console.print(Panel(t,
            title='[bold cyan]Stage 01 — Dateierkennung & Beweissicherung[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage02_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        if not ctx.ram_dump_path:
            t.add_row('Status', Text('⏭  Kein RAM-Dump übergeben — übersprungen', style='dim'))
            t.add_row('Hinweis', 'RAM-Analyse nur bei Live-System-Dumps aussagekräftig')
        else:
            total = sum(len(v) for v in ctx.memory_results.values())
            t.add_row('RAM-Dump', str(ctx.ram_dump_path.name))
            t.add_row('Einträge gesamt', f'{total:,}')
            for plugin, entries in ctx.memory_results.items():
                if entries:
                    t.add_row(f'  {plugin}', f'{len(entries):,} Einträge')
        console.print(Panel(t,
            title='[bold cyan]Stage 02_mem — RAM-Analyse (Volatility3)[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage02_partition_detail(self, ctx) -> None:
        layout = getattr(ctx, 'partition_layout', [])
        if not layout:
            return
        t = Table(box=box.SIMPLE, show_header=True, border_style='cyan', expand=True)
        t.add_column('Nr',          style='bold', width=4)
        t.add_column('Offset',      width=12)
        t.add_column('Größe',       width=12)
        t.add_column('Dateisystem', width=12)
        t.add_column('Rolle',       width=12)
        t.add_column('OS',          min_width=18)
        t.add_column('Tool',        width=10)

        for p in layout:
            role_style = 'green' if p['role'] == 'ROOT/DATA' else ('dim' if p['role'] in ('SWAP','BOOT') else 'yellow')
            tool_txt   = p['tool'] if p['analysable'] else '—'
            tool_style = 'green' if p['analysable'] else 'dim'
            t.add_row(
                str(p['index']),
                f"{p['offset']:,}",
                f"{p['size_mb']:.0f} MB",
                p['fs_type'],
                Text(p['role'], style=role_style),
                p['os_name'] or '—',
                Text(tool_txt, style=tool_style),
            )

        multi_os = getattr(ctx, 'multi_os_detected', False)
        n_anal   = len(getattr(ctx, 'analysis_partitions', []))
        console.print(Panel(
            t,
            title='[bold cyan]Stage 02 — Partition-Layout[/bold cyan]',
            border_style='cyan', padding=(0, 1),
            subtitle=f'Analysierbar: {n_anal}  |  Multi-OS: {"⚠️ Ja" if multi_os else "Nein"}',
        ))

    def show_stage03_detail(self, ctx) -> None:
        from rich.console import Group

        partition_profiles = getattr(ctx, 'partition_profiles', [])
        shadow_mtime       = getattr(ctx, 'shadow_mtime', '')

        def _build_profile_table(profile: dict, is_primary: bool) -> Table:
            t = Table(box=box.ROUNDED, show_header=False,
                      border_style='dim', expand=True)
            t.add_column('Feld', style='bold', min_width=22)
            t.add_column('Wert', style='white')

            t.add_row('Betriebssystem', profile.get('os_name')       or 'Unbekannt')
            t.add_row('OS-Familie',     profile.get('os_family')     or 'Unbekannt')
            t.add_row('Kernel',         profile.get('kernel_version') or 'Unbekannt')
            install_time = profile.get('install_time', '')
            t.add_row('Installiert am', install_time if install_time else Text('nicht bestimmbar', style='dim'))
            usage = profile.get('usage_period', {})
            t.add_row('Erste Aktivität', usage.get('first_activity') or Text('nicht bestimmbar', style='dim'))
            t.add_row('Letzte Aktivität', usage.get('last_activity') or Text('nicht bestimmbar', style='dim'))
            t.add_row('Hostname',       profile.get('hostname')       or 'Unbekannt')
            tz = profile.get('timezone_display') or profile.get('timezone') or 'UTC'
            t.add_row('Zeitzone', tz)
            mid = profile.get('machine_id', '')
            t.add_row('Machine-ID',  mid[:32] + ('...' if len(mid) > 32 else '') if mid else Text('nicht vorhanden', style='dim'))
            ips = profile.get('ip_addresses', [])
            t.add_row('IP-Adressen', ', '.join(ips[:5]) if ips else Text('nicht vorhanden', style='dim'))

            # Strukturierte Netzwerkkonfiguration
            net = profile.get('net_config', {})
            if net:
                t.add_row('─── Netzwerkkonfiguration ───', '')
                if net.get('interfaces'):
                    t.add_row('Interfaces',   ', '.join(net['interfaces'][:6]))
                if net.get('dns_servers'):
                    t.add_row('DNS-Server',   ', '.join(net['dns_servers'][:4]))
                if net.get('search_domains'):
                    t.add_row('Suchdomänen',  ', '.join(net['search_domains'][:3]))
                if net.get('gateway'):
                    t.add_row('Gateway',      net['gateway'])
                if net.get('mac_hints'):
                    t.add_row('MAC-Hinweise', ', '.join(net['mac_hints'][:3]) + '  (aus DHCP/NM)')

            virt = profile.get('virtualization', '')
            if virt:
                virt_style = 'dim' if virt == 'Bare-Metal' else 'cyan'
                t.add_row('Umgebung', Text(virt, style=virt_style))

            # SSH-Konfiguration
            ssh = profile.get('ssh_config', {})
            if ssh:
                t.add_row('─── SSH-Konfiguration ───', '')
                root_login = ssh.get('permit_root_login', '')
                if root_login:
                    rl_style = 'bold red' if root_login.lower() in ('yes',) else 'green'
                    t.add_row('Root-Login', Text(root_login, style=rl_style))
                pw_auth = ssh.get('password_auth', '')
                if pw_auth:
                    pa_style = 'yellow' if pw_auth.lower() == 'yes' else 'green'
                    t.add_row('Passwort-Auth', Text(pw_auth, style=pa_style))
                if ssh.get('port', '') not in ('22', ''):
                    t.add_row('SSH-Port', Text(ssh['port'], style='bold yellow'))
                if ssh.get('allow_users'):
                    t.add_row('AllowUsers', ssh['allow_users'])
                if ssh.get('deny_users'):
                    t.add_row('DenyUsers', Text(ssh['deny_users'], style='yellow'))

            # ── Kernel & Boot ─────────────────────────────────────────────
            all_k = profile.get('all_kernels', [])
            if all_k:
                t.add_row('─── Kernel & Boot ───', '')
                t.add_row('Installierte Kernel', ', '.join(all_k))
                grub = profile.get('grub_config', {})
                if grub.get('active_kernel'):
                    t.add_row('GRUB-Default', grub['active_kernel'])
                if grub.get('fallback_kernels'):
                    t.add_row('Fallback-Kernel', ', '.join(grub['fallback_kernels']))
                if grub.get('antiforensic_params'):
                    t.add_row(
                        Text('⚠️  GRUB Anti-Forensik', style='bold red'),
                        Text(', '.join(grub['antiforensic_params']), style='bold red'),
                    )
                # Kernel Compile Flags
                flags_map = profile.get('kernel_compile_flags', {})
                for kver, kinfo in flags_map.items():
                    if kinfo.get('has_antiforensics'):
                        t.add_row(
                            Text('⚠️  Kernel-Flags', style='bold red'),
                            Text(', '.join(kinfo['active_flags']), style='red'),
                        )

            # Swap-Konfiguration
            swap = profile.get('swap_config', {})
            if swap:
                if swap.get('found'):
                    entries = swap.get('entries', [])
                    swap_str = ', '.join(
                        f"{e['type']}:{e['path']}" for e in entries[:3]
                    )
                    t.add_row('Swap', Text(f'✅  {swap_str}', style='green'))
                else:
                    t.add_row('Swap', Text('❌  Kein Swap konfiguriert', style='yellow'))

            # Reboot ausstehend
            if profile.get('reboot_pending'):
                t.add_row(
                    Text('⚠️  Pending Reboot', style='bold yellow'),
                    Text('Kernel-Update installiert — kein Neustart erfolgt', style='yellow'),
                )

            # Geladener Kernel laut Logs
            loaded_k = profile.get('loaded_kernel', '')
            if loaded_k:
                grub_default = profile.get('grub_config', {}).get('active_kernel', '')
                if grub_default and loaded_k != grub_default:
                    t.add_row(
                        Text('⚠️  Kernel-Diskrepanz', style='bold red'),
                        Text(f'GRUB={grub_default} | Geladen={loaded_k}', style='red'),
                    )
                else:
                    t.add_row('Geladen (laut Logs)', loaded_k)

            # Installierte Pakete
            pkgs = profile.get('packages', {})
            if pkgs.get('count', 0):
                notable_str = ', '.join(pkgs.get('notable', [])[:6]) or '—'
                t.add_row('Pakete', f"{pkgs['count']} installiert  |  notable: {notable_str}")

            # Services
            svcs = profile.get('services', {})
            if svcs.get('enabled'):
                t.add_row('Services aktiv', ', '.join(svcs['enabled'][:8]))
            non_std = svcs.get('non_standard', [])
            if non_std:
                ns_str = ', '.join(non_std[:8])
                if len(non_std) > 8:
                    ns_str += f'  [dim](+{len(non_std) - 8} weitere)[/dim]'
                t.add_row('[bold yellow]⚠ Non-Standard Services[/bold yellow]',
                          f'[bold yellow]{ns_str}[/bold yellow]')

            users            = profile.get('users', [])
            notable_users    = profile.get('notable_users', [])
            unexpected_users = profile.get('unexpected_users', [])
            t.add_row('─── Nutzer-Profil ───', '')
            if users:
                system_count  = sum(1 for u in users if u.get('is_system'))
                regular_count = len(users) - system_count
                login_allowed = [u['name'] for u in users if u.get('login_allowed')]
                t.add_row('Nutzer gesamt',    f'{len(users)}  ({system_count} System, {regular_count} regulär)')
                t.add_row('Login-berechtigt', ', '.join(login_allowed[:5]) or '—')
                # Pro-User Details
                for u in users[:10]:
                    if u.get('is_system') and not u.get('is_unexpected'):
                        continue  # System-User überspringen außer wenn verdächtig
                    icon  = '✅' if u.get('has_password') else '❌'
                    sudo  = ' 🔑sudo' if u.get('has_sudo') else ''
                    ct    = f'  erstellt: {u["created_at"]}' if u.get('created_at') else ''
                    ll    = f'  letzter Login: {u["last_login_time"]}' if u.get('last_login_time') else ''
                    host  = f' von {u["last_login_host"]}' if u.get('last_login_host') else ''
                    meth  = f'  [{", ".join(u.get("login_methods", []))}]' if u.get('login_methods') else ''
                    hist  = f'  history: {",".join(u.get("shell_histories",[]))}' if u.get('shell_histories') else ''
                    grps  = f'  gruppen: {",".join(u.get("groups",[])[:4])}' if u.get('groups') else ''
                    detail = f'{ct}{ll}{host}{meth}{sudo}{hist}{grps}'
                    style  = 'bold red' if u.get('is_unexpected') else ('bold yellow' if not u.get('is_system') else 'white')
                    t.add_row(f'{icon} {u["name"]}', Text(detail.strip(), style=style))

                # Unbekannte System-User (forensisch verdächtig)
                if unexpected_users:
                    t.add_row('⚠️  Unbekannte Sys-User',
                              Text(', '.join(unexpected_users), style='bold red'))
            else:
                t.add_row('Nutzer', Text('nicht vorhanden', style='dim'))
            sm = profile.get('shadow_mtime', '')
            _p_lbl = f"Partition {profile.get('partition_index', '?')}"
            t.add_row('/etc/shadow',
                      f'Letzte Änderung: {sm}   [TSK istat, {_p_lbl}]'
                      if sm else Text('nicht vorhanden', style='dim'))
            return t

        inner_panels = []
        for profile in partition_profiles:
            is_primary = profile.get('is_primary', False)
            idx   = profile.get('partition_index', '?')
            fs    = profile.get('fs_type', '')
            size  = profile.get('size_mb', 0)

            if is_primary:
                p_title  = f'[bold green]⭐ Primäre Partition  [{idx}]  {fs}  ·  {size:,.0f} MB[/bold green]'
                p_border = 'green'
            else:
                role     = profile.get('role', '')
                role_str = f'  ·  {role}' if role else ''
                hint     = '  (Boot-Partition — kein OS erwartet)' if role == 'BOOT' else ''
                p_title  = f'[cyan]Partition  [{idx}]  {fs}  ·  {size:,.0f} MB{role_str}{hint}[/cyan]'
                p_border = 'dim'

            tbl = _build_profile_table(profile, is_primary)
            inner_panels.append(Panel(tbl, title=p_title,
                                      border_style=p_border, padding=(0, 1)))

        # Spacer zwischen den inneren Panels
        spaced: list = []
        for i, p in enumerate(inner_panels):
            spaced.append(p)
            if i < len(inner_panels) - 1:
                spaced.append(Text(''))

        console.print(Panel(
            Group(*spaced) if spaced else Text('Kein Profil verfügbar'),
            title='[bold cyan]Stage 03 — System-Profiling[/bold cyan]',
            border_style='cyan', padding=(1, 1),
        ))

    def show_stage035_detail(self, ctx) -> None:
        checks        = getattr(ctx, 'basic_checks', [])
        anomaly_count = getattr(ctx, 'basic_check_anomalies', 0)
        os_label      = ctx.os_name or ctx.os_family or 'Unbekannt'

        if not checks:
            t = Table(box=box.SIMPLE, show_header=False, expand=True)
            t.add_column('Info', style='dim')
            t.add_row(f'OS-Familie "{ctx.os_family}" — kein Profil vorhanden')
            t.add_row('Unterstützte Familien: debian · rhel · arch · alpine')
            t.add_row('Basic Checks werden durchgeführt sobald OS erkannt wird.')
            console.print(Panel(
                t,
                title=f'[bold cyan]Stage 03.5 — Basic Checks ({os_label})[/bold cyan]',
                border_style='cyan', padding=(0, 1),
                subtitle='[dim]⏭ Übersprungen[/dim]',
            ))
            return

        t = Table(box=box.SIMPLE, show_header=True, border_style='cyan', expand=True)
        t.add_column('Service/Log',  min_width=22)
        t.add_column('Erwartet',     width=10)
        t.add_column('Gefunden',     width=10)
        t.add_column('Status',       min_width=30)

        for c in checks:
            expected_txt = Text('Pflicht' if c['expected'] else '—',
                                style='dim' if not c['expected'] else 'white')
            found_txt    = Text('✅ Ja' if c['found'] else '❌ Nein',
                                style='green' if c['found'] else 'red')
            if c['status'] == 'nicht installiert':
                status_style = 'dim'
            elif not c['anomaly']:
                status_style = 'green'
            else:
                status_style = 'bold yellow'
            t.add_row(c['service'], expected_txt, found_txt,
                      Text(c['status'], style=status_style))

        console.print(Panel(
            t,
            title=f'[bold cyan]Stage 03.5 — Basic Checks ({os_label})[/bold cyan]',
            border_style='cyan', padding=(0, 1),
            subtitle=f'[bold yellow]Anomalien: {anomaly_count}[/bold yellow]' if anomaly_count else '[bold green]Keine Anomalien ✅[/bold green]',
            width=console.width,
        ))

    def show_stage05_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False,
                  border_style='cyan', expand=True)
        t.add_column('Feld',  style='bold', min_width=30)
        t.add_column('Wert',  style='white')

        # Partitionen
        for p in ctx.tsk_partitions:
            status = '✅ analysiert' if p['status'] == 'analysiert' else '⏭  übersprungen'
            info   = f"offset={p['offset']}  fs={p['fs_type']}"
            if p['status'] == 'analysiert':
                info += f"  →  {p['files']:,} Einträge  ({p.get('deleted', 0)} gelöscht)"
            t.add_row(f"Partition {p['offset']}", f"{status}  {info}")

        t.add_row('', '')
        t.add_row('Log-Dateien extrahiert', f"{ctx.tsk_log_files_extracted:,}")

        # Liste ist vollstaendig (Originalpfade) — Anzeige auf 15 begrenzen
        for fname in ctx.tsk_extracted_filenames[:15]:
            t.add_row('', f"  → {fname}")
        if len(ctx.tsk_extracted_filenames) > 15:
            t.add_row('', f"  … und {len(ctx.tsk_extracted_filenames) - 15:,} weitere (siehe extraction_manifest.json)")

        t.add_row('', '')
        t.add_row('Gelöschte Dateien gefunden',
                  f"{ctx.tsk_deleted_found:,}")
        t.add_row('✅ Wiederhergestellt',
                  Text(f"{ctx.tsk_deleted_recovered:,}", style='bold green'))
        t.add_row('❌ Nicht wiederherstellbar',
                  Text(f"{ctx.tsk_deleted_not_recovered:,}  (Sektoren überschrieben)",
                       style='bold red'))

        console.print(Panel(
            t,
            title='[bold cyan]Stage 05 — Disk-Artefakt-Extraktion (TSK)[/bold cyan]',
            border_style='cyan',
            padding=(0, 1),
        ))

    def show_mactime_sorter_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False,
                  border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')

        if ctx.tsk_mactime_events:
            t.add_row('MACtime-Timeline',
                      Text(f'✅  {ctx.tsk_mactime_events:,} Einträge', style='green'))
        else:
            t.add_row('MACtime-Timeline',
                      Text('❌  mactime nicht verfügbar', style='dim'))

        if ctx.tsk_sorter_ran and ctx.tsk_sorter_categories:
            t.add_row('Sorter', Text(f'✅  {len(ctx.tsk_sorter_categories)} Kategorien', style='green'))
        elif ctx.tsk_sorter_ran:
            t.add_row('Sorter', Text('✅  gelaufen', style='green'))
        else:
            t.add_row('Sorter', Text('❌  sorter nicht verfügbar', style='dim'))

        console.print(Panel(
            t,
            title='[bold cyan]MACtime & Sorter[/bold cyan]',
            border_style='cyan',
            padding=(0, 1),
        ))

    def show_stage07_detail(self, ctx) -> None:
        from collections import Counter
        type_counts = Counter(ioc.type for ioc in ctx.iocs)
        ip_total    = type_counts.get('ip', 0)
        ip_private  = sum(1 for ioc in ctx.iocs
                          if ioc.type == 'ip' and PRIVATE_IPS.match(ioc.value))
        ip_public   = ip_total - ip_private
        cves        = [ioc.value for ioc in ctx.iocs if ioc.type == 'cve'][:5]

        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        t.add_row('IPs gesamt',   f'{ip_total:,}')
        t.add_row('  öffentlich', Text(f'{ip_public:,}  ✅', style='green'))
        t.add_row('  privat',     Text(f'{ip_private:,}  ⚠️  False Positives möglich', style='yellow'))
        t.add_row('Domains',      f"{type_counts.get('domain', 0):,}")
        t.add_row('Hashes',       f"{type_counts.get('hash_md5', 0) + type_counts.get('hash_sha256', 0):,}")
        t.add_row('E-Mails',      f"{type_counts.get('email', 0):,}")
        t.add_row('CVEs',         f"{type_counts.get('cve', 0):,}")
        if cves:
            t.add_row('  Beispiele', ', '.join(cves))
        t.add_row('Gesamt',       Text(f"{len(ctx.iocs):,} IOCs", style='bold'))
        t.add_row('Qualität',     Text(ctx.ioc_quality,
                  style='green' if ctx.ioc_quality == 'HOCH' else 'yellow'))
        t.add_row('', '')
        if ctx.bulk_extractor_ran:
            t.add_row('Bulk-Extractor',
                      Text(f'✅  {ctx.bulk_extractor_iocs:,} IOCs (direkt aus Image)',
                           style='green'))
        else:
            t.add_row('Bulk-Extractor',
                      Text('⚠️  nicht installiert — nur Regex-Extraktion',
                           style='yellow'))
        console.print(Panel(t,
            title='[bold cyan]Stage 07 — IOC-Extraktion[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage08_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False,
                  border_style='cyan', expand=True)
        t.add_column('Feld',  style='bold', min_width=28)
        t.add_column('Wert',  style='white')

        count = len(ctx.normalized_events)
        t.add_row('Events normalisiert', f'{count:,}')
        t.add_row('Systemzeitzone',      f'{ctx.timezone}  ({ctx.timezone_offset})')
        t.add_row('Timestamps → UTC',    '✅')
        t.add_row('Lokalzeit gespeichert', f'✅  ({ctx.timezone_offset})')
        if ctx.earliest_event:
            t.add_row('Frühestes Event', ctx.earliest_event)
        if ctx.latest_event:
            t.add_row('Letztes Event',   ctx.latest_event)

        console.print(Panel(
            t,
            title='[bold cyan]Stage 08 — Datennormalisierung[/bold cyan]',
            border_style='cyan',
            padding=(0, 1),
        ))

    def show_stage09_detail(self, ctx) -> None:
        from collections import Counter
        type_counts = Counter(h.get('type', 'unbekannt') for h in ctx.antiforensics_hits)

        # Typ-Labels: Icon, Farbe, Lesbare Bezeichnung
        TYPE_META = {
            'devnull_symlink':              ('🔴', 'red',     '/dev/null Symlinks'),
            'rc_local_antiforensics':       ('🔴', 'red',     'rc.local Manipulation'),
            'grub_memory_wipe':             ('🔴', 'red',     'GRUB Memory-Wipe-Params'),
            'kernel_compile_antiforensics': ('🟠', 'orange3', 'Kernel Compile-Flags'),
            'execstop_wiping':              ('🔴', 'red',     'ExecStop Wiping-Tool'),
            'swap_missing':                 ('🟡', 'yellow',  'Swap fehlt'),
            'kernel_discrepancy':           ('🟠', 'orange3', 'Kernel-Diskrepanz'),
            'pending_reboot':               ('🟡', 'yellow',  'Pending Reboot'),
            'journal_wtmp_mismatch':        ('🔴', 'red',     'Journal/wtmp Mismatch'),
            'yara_match':                   ('🟡', 'yellow',  'YARA-Treffer'),
            'timestomping':                 ('🔴', 'red',     'Timestomping'),
            'log_deletion':                 ('🔴', 'red',     'Log-Wiping'),
            'rootkit_indicator':            ('🔴', 'red',     'Rootkit-Indikator'),
            'secure_delete':                ('🟠', 'orange3', 'Secure-Delete'),
        }

        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=28)
        t.add_column('Wert', style='white')
        t.add_row('Treffer gesamt', Text(f'{len(ctx.antiforensics_hits):,}', style='bold'))
        t.add_row('', '')
        for hit_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            icon, color, label = TYPE_META.get(hit_type, ('🔵', 'dim', hit_type))
            # False-Positive-Hinweis nur fuer YARA/vmdetect
            fp_note = '  ⚠️  wahrsch. False Positives' if (
                'yara' in hit_type or 'vmdetect' in hit_type.lower()
            ) else ''
            t.add_row(
                f'  {icon}  {label}',
                Text(f'{count:,}{fp_note}', style=color),
            )
        # ── Top-5 Treffer Detail-Ansicht ─────────────────────────────────────
        # Sortierung: critical > high > medium > low — YARA-Treffer ans Ende
        SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        SEVERITY_STYLE = {'critical': 'bold red', 'high': 'red', 'medium': 'yellow', 'low': 'dim'}

        non_yara = [h for h in ctx.antiforensics_hits
                    if h.get('type') not in ('yara_match',)]
        yara_hits = [h for h in ctx.antiforensics_hits
                     if h.get('type') == 'yara_match']

        top_hits = sorted(
            non_yara,
            key=lambda h: SEVERITY_ORDER.get(h.get('severity', 'low'), 9)
        )[:5]

        # Falls weniger als 5 Non-YARA-Treffer → YARA auffuellen
        if len(top_hits) < 5:
            top_hits += yara_hits[:5 - len(top_hits)]

        if top_hits:
            t.add_row('─── Top-Treffer (Detail) ───', '')
            for i, hit in enumerate(top_hits, 1):
                sev    = hit.get('severity', 'low')
                htype  = hit.get('type', 'unbekannt')
                icon, color, label = TYPE_META.get(htype, ('🔵', 'dim', htype))
                sev_style = SEVERITY_STYLE.get(sev, 'white')
                sev_upper = sev.upper()

                # Zeile 1: Nummer + Typ + Severity
                t.add_row(
                    Text(f'  {i}.  {icon}  {label}', style='bold'),
                    Text(f'[{sev_upper}]', style=sev_style),
                )
                # Zeile 2: Datei-Pfad (gekuerzt)
                fpath = hit.get('file', '')
                if fpath:
                    t.add_row(
                        Text('      Datei', style='dim'),
                        Text(fpath[:90], style='dim'),
                    )
                # Zeile 3: Details (auf 110 Zeichen kuerzen)
                details = hit.get('details', '')
                if details:
                    t.add_row(
                        Text('      Detail', style='dim'),
                        Text(details[:110], style=color),
                    )
                # Leerzeile zwischen Treffern (ausser nach letztem)
                if i < len(top_hits):
                    t.add_row('', '')

        t.add_row('', '')
        t.add_row('Hinweis', 'YARA optimiert fuer Malware-Erkennung.')
        t.add_row('', 'vmdetect-Treffer auf .py-Dateien sind bekannte False Positives.')
        console.print(Panel(t,
            title='[bold cyan]Stage 09 — Anti-Forensics[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage85_detail(self, ctx) -> None:
        findings = getattr(ctx, 'forensic_findings', None) or []

        SEV_ICON  = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        SEV_COLOR = {'CRITICAL': 'red', 'HIGH': 'orange3', 'MEDIUM': 'yellow', 'LOW': 'green'}

        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=28)
        t.add_column('Wert', style='white')

        if not findings:
            t.add_row('Befunde gesamt', Text('0 — keine Anomalien gefunden', style='green'))
        else:
            from collections import Counter
            sev_counts  = Counter(f.severity for f in findings)
            rule_counts = Counter(f.rule for f in findings)

            t.add_row('Befunde gesamt', Text(f'{len(findings):,}', style='bold'))
            t.add_row('', '')

            # Severity-Übersicht
            for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
                cnt = sev_counts.get(sev, 0)
                if cnt:
                    icon  = SEV_ICON.get(sev, '🔵')
                    color = SEV_COLOR.get(sev, 'white')
                    t.add_row(f'  {icon}  {sev}', Text(f'{cnt:,}', style=color))

            t.add_row('', '')

            # Top-5 Befunde
            top = findings[:5]
            for i, f in enumerate(top, 1):
                icon  = SEV_ICON.get(f.severity, '🔵')
                color = SEV_COLOR.get(f.severity, 'white')
                t.add_row(
                    Text(f'  {i}.  {icon}  {f.rule}', style='bold'),
                    Text(f'[{f.severity}]', style=color),
                )
                t.add_row(
                    Text('      Datei',   style='dim'),
                    Text(f.file[:90],    style='dim'),
                )
                t.add_row(
                    Text('      Befund',  style='dim'),
                    Text(f.description[:110], style=color),
                )
                if i < len(top):
                    t.add_row('', '')

            t.add_row('', '')
            t.add_row('Ausgabe', 'forensic_findings.csv + forensic_findings.xlsx')

        console.print(Panel(
            t,
            title='[bold cyan]Stage 8.5 — Forensische Timeline-Analyse[/bold cyan]',
            border_style='cyan',
            padding=(0, 1),
        ))

    def show_stage12_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        if ctx.enriched_summary:
            lines = ctx.enriched_summary.splitlines()
            t.add_row('Status',   Text('✅  Executive Summary erstellt', style='green'))
            t.add_row('Umfang',   f'{len(lines)} Zeilen')
            t.add_row('Enthält',  'System-Info, Statistiken, Top-Funde, Anti-Forensics-Warnungen')
        else:
            t.add_row('Status', Text('⚠️  Keine Summary erstellt', style='yellow'))
        console.print(Panel(t,
            title='[bold cyan]Stage 12 — Ergebnis-Aggregation[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage13_detail(self, ctx) -> None:
        from stages.stage13_quality import evaluate_quality
        quality = evaluate_quality(ctx)
        q_style = {'SEHR GUT': 'bold green', 'GUT': 'bold yellow',
                   'EINGESCHRÄNKT': 'bold orange3', 'KRITISCH': 'bold red'}.get(quality, 'white')

        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        t.add_row('Gesamtbewertung', Text(quality, style=q_style))
        t.add_row('Stufen-Fehler',   str(len(ctx.stage_errors)))
        warnings = {k: v for k, v in ctx.stage_status.items() if 'ÜBERSPRUNGEN' in v}
        t.add_row('Warnungen',       str(len(warnings)))
        for stage, msg in list(warnings.items())[:3]:
            t.add_row(f'  {stage}', msg[:80])
        if ctx.stage_errors:
            t.add_row('', '')
            for stage, err in list(ctx.stage_errors.items())[:3]:
                t.add_row(Text(f'  ❌ {stage}', style='red'), err[:80])
        console.print(Panel(t,
            title='[bold cyan]Stage 13 — Qualitätsprüfung[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage14_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        if ctx.case_dir:
            report    = ctx.case_dir / 'report.pdf'
            coc       = ctx.case_dir / 'chain_of_custody.pdf'
            js_report = ctx.case_dir / 'pipeline_report.json'
            t.add_row('report.pdf',
                      Text(f'✅  {report}', style='green') if report.exists()
                      else Text('❌  nicht erstellt', style='red'))
            t.add_row('chain_of_custody.pdf',
                      Text(f'✅  {coc}', style='green') if coc.exists()
                      else Text('❌  nicht erstellt', style='red'))
            t.add_row('pipeline_report.json',
                      Text(f'✅  {js_report}', style='green') if js_report.exists()
                      else Text('❌  nicht erstellt', style='red'))
            # Neue separate CSV-Dateien
            for fname in ('activity_timeline.csv', 'system_reboots.csv',
                          'login_events.csv', 'system_crashes.csv',
                          'filesystem_timeline.csv'):
                p = ctx.case_dir / fname
                t.add_row(fname,
                          Text(f'✅  {p}', style='green') if p.exists()
                          else Text('❌  nicht erstellt', style='red'))
        ts_status = ctx.stage_status.get('stage_14_timesketch', '')
        if 'ÜBERSPRUNGEN' in ts_status or not ts_status:
            t.add_row('Timesketch Upload', Text('⏭  übersprungen (--no-timesketch)', style='dim'))
        else:
            t.add_row('Timesketch Upload', Text('✅  erfolgreich', style='green'))
        console.print(Panel(t,
            title='[bold cyan]Stage 14 — Export & Archivierung[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_parser_detail(self, ctx) -> None:
        active   = ctx.parser_file_map   # {name: {'count': int, 'files': [str]}}
        all_names = ctx.all_parser_names
        inactive = [n for n in all_names if n not in active]

        t = Table(box=box.ROUNDED, show_header=True,
                  border_style='cyan', expand=True)
        t.add_column('Parser',  style='bold', min_width=18)
        t.add_column('Events',  justify='right', width=10)
        t.add_column('Datei(en)', style='dim')

        for name, info in sorted(active.items(), key=lambda x: -x[1]['count']):
            files = info['files']
            path_str = files[0] if len(files) == 1 else f'{len(files)} Dateien'
            t.add_row(
                Text(f'✅  {name}', style='bold green'),
                f"{info['count']:,}",
                path_str,
            )

        if inactive:
            inactive_rows = [inactive[i:i+4] for i in range(0, len(inactive), 4)]
            inactive_lines = '\n'.join(', '.join(row) for row in inactive_rows)
            t.add_row('', '', '')
            t.add_row(
                Text(f'❌  NICHT GEFUNDEN ({len(inactive)})', style='bold red'),
                '',
                inactive_lines,
            )

        console.print(Panel(
            t,
            title=f'[bold cyan]Stage 6 — Parser Detail  '
                  f'({len(active)} von {len(all_names)} aktiv)[/bold cyan]',
            border_style='cyan',
            padding=(0, 1),
        ))

    # ── Private ───────────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    def _render(self) -> Panel:
        self._spin_idx = (self._spin_idx + 1) % len(SPINNERS)
        spin = SPINNERS[self._spin_idx]
        elapsed = _fmt_time(time.time() - self._start)

        t = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style='bold white on dark_blue',
            border_style='bright_blue',
            expand=True,
        )
        t.add_column('Stage', style='bold cyan', width=6,  justify='center')
        t.add_column('Bezeichnung',               min_width=30)
        t.add_column('Status',                    width=24)
        t.add_column('Zeit',                      width=7, justify='right')

        for key, (num, name) in STAGE_INFO.items():
            s = self.states[key]

            if s.status == 'waiting':
                status = Text('⏸  wartend', style='dim')
                dur    = ''
            elif s.status == 'running':
                running = time.time() - (s.start_time or time.time())
                status  = Text(f'{spin}  läuft...', style='bold yellow')
                dur     = _fmt_time(running)
            elif s.status == 'ok':
                label  = s.note if s.note else 'OK'
                status = Text(f'✅  {label}', style='bold green')
                dur    = f'{s.duration:.0f}s' if s.duration else ''
            elif s.status == 'skipped':
                status = Text('⏭  übersprungen', style='dim')
                dur    = ''
            else:
                status = Text('❌  FEHLER', style='bold red')
                dur    = f'{s.duration:.0f}s' if s.duration else ''

            t.add_row(num, name, status, dur)

        subtitle = f'[dim]{self.message}[/dim]' if self.message else ''
        title    = (
            f'[bold bright_blue]DFIR Pipeline v3.0[/bold bright_blue]'
            f'  [dim]│  {self.image_name}  │  {elapsed}[/dim]'
        )
        inner = Table.grid()
        inner.add_row(t)
        if subtitle:
            inner.add_row(Text(f'  {self.message}', style='dim'))

        return Panel(inner, title=title, border_style='bright_blue', padding=(0, 1))


def _fmt_time(seconds: float) -> str:
    s = int(seconds)
    return f'{s // 60:02d}:{s % 60:02d}'
