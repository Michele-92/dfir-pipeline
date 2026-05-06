import time
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

    def stop(self) -> None:
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
