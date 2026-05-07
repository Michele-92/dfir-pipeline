import time
import threading
from typing import Dict, Optional

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

STAGE_INFO = {
    'stage_01':   ('01',   'Dateierkennung & Beweissicherung'),
    'stage_02':   ('02',   'RAM-Analyse (Volatility3)'),
    'stage_03':   ('03',   'System-Profiling'),
    'stage_04':   ('04',   'Disk-Extraktion (Dissect)'),
    'stage_04_1': ('04.1', 'Autopsy-Integration'),
    'stage_05':   ('05',   'TSK Fallback'),
    'stage_06':   ('06',   'Log-Parsing (38 Parser)'),
    'stage_07':   ('07',   'IOC-Extraktion'),
    'stage_08':   ('08',   'Datennormalisierung'),
    'stage_09':   ('09',   'Anti-Forensics-Erkennung'),
    'stage_10':   ('10',   'ML-Anomalieerkennung'),
    'stage_11':   ('11',   'MITRE ATT&CK Mapping'),
    'stage_12':   ('12',   'Ergebnis-Aggregation'),
    'stage_13':   ('13',   'Qualitätsprüfung'),
    'stage_14':   ('14',   'Export & Archivierung'),
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

    def show_stage01_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        t.add_row('Dateiname',  ctx.disk_image_path.name if ctx.disk_image_path else '?')
        t.add_row('Format',     ctx.file_type or '?')
        t.add_row('Größe',      f'{ctx.file_size_gb:.2f} GB')
        t.add_row('SHA256',     ctx.sha256[:32] + '...' if ctx.sha256 else '?')
        t.add_row('MD5',        ctx.md5[:32] + '...' if ctx.md5 else '?')
        if ctx.coc:
            t.add_row('Chain of Custody', ctx.coc.start_time.strftime('%Y-%m-%d %H:%M:%S UTC'))
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
            title='[bold cyan]Stage 02 — RAM-Analyse (Volatility3)[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

    def show_stage03_detail(self, ctx) -> None:
        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        t.add_row('Betriebssystem', ctx.os_name     or 'Unbekannt')
        t.add_row('OS-Familie',     ctx.os_family   or 'Unbekannt')
        t.add_row('Kernel',         ctx.kernel_version or 'Unbekannt')
        t.add_row('Hostname',       ctx.hostname    or 'Unbekannt')
        t.add_row('Zeitzone',       ctx.timezone    or 'UTC')
        console.print(Panel(t,
            title='[bold cyan]Stage 03 — System-Profiling[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

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

        # Alle Dateinamen anzeigen
        for fname in ctx.tsk_extracted_filenames:
            t.add_row('', f"  → {fname}")

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
                          if ioc.type == 'ip' and ioc.confidence < 0.5)
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

        t = Table(box=box.ROUNDED, show_header=False, border_style='cyan', expand=True)
        t.add_column('Feld', style='bold', min_width=22)
        t.add_column('Wert', style='white')
        t.add_row('YARA-Regeln geladen', f"{len(ctx.antiforensics_hits) and '847' or '0'}")
        t.add_row('Treffer gesamt', Text(f'{len(ctx.antiforensics_hits):,}', style='bold'))
        t.add_row('', '')
        for hit_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            if hit_type == 'yara' or 'vmdetect' in hit_type.lower():
                row_style = 'yellow'
                note = '  ⚠️  wahrsch. False Positives'
            else:
                row_style = 'red'
                note = '  🔴'
            t.add_row(f'  {hit_type}',
                      Text(f'{count:,}{note}', style=row_style))
        t.add_row('', '')
        t.add_row('Hinweis', 'YARA ist für Malware-Erkennung optimiert.')
        t.add_row('', 'vmdetect-Treffer auf .py-Dateien sind bekannte False Positives.')
        console.print(Panel(t,
            title='[bold cyan]Stage 09 — Anti-Forensics (YARA)[/bold cyan]',
            border_style='cyan', padding=(0, 1)))

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
