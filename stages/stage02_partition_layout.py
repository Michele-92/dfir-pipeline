import logging
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional

from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

_TSK_PREFIX = '/usr/local/bin/'

def _tsk(cmd: str) -> str:
    local = Path(f'{_TSK_PREFIX}{cmd}')
    return str(local) if local.exists() else cmd


TOOL_POOL = {
    'ext4':  ('tsk',    'TSK 4.15 — ext-Dateisysteme'),
    'ext3':  ('tsk',    'TSK 4.15 — ext-Dateisysteme'),
    'ext2':  ('tsk',    'TSK 4.15 — ext-Dateisysteme'),
    'ntfs':  ('tsk',    'TSK 4.15 — NTFS'),
    'fat32': ('tsk',    'TSK 4.15 — FAT32'),
    'exfat': ('tsk',    'TSK 4.15 — exFAT'),
    'vfat':  ('tsk',    'TSK 4.15 — FAT/vFAT'),
    'xfs':   ('xfs_db', 'xfs_db — XFS-nativ (xfsprogs)'),
    'btrfs': ('btrfs',  'btrfs-progs — Btrfs-nativ'),
}

ANALYSABLE_FS = {'ext4', 'ext3', 'ext2', 'ntfs', 'fat32', 'exfat', 'vfat', 'xfs', 'btrfs'}
SKIP_ROLES    = {'SWAP', 'UNBEKANNT'}


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 2: Partition-Layout-Analyse')
    if not ctx.disk_image_path:
        ctx.stage_status['stage_02'] = 'ÜBERSPRUNGEN — kein Image'
        return ctx

    partitions = _read_partitions(ctx.disk_image_path)
    if not partitions:
        log.warning('  Keine Partitionen gefunden')
        ctx.stage_status['stage_02'] = 'ÜBERSPRUNGEN — keine Partitionen'
        return ctx

    layout = []
    for part in partitions:
        offset   = part['start']
        size_mb  = (part['size'] * 512) / (1024 * 1024)
        fs_type  = _detect_filesystem(ctx.disk_image_path, offset)
        role     = _detect_role(fs_type, size_mb)
        os_name, os_family = '', ''

        if fs_type in ANALYSABLE_FS and role not in SKIP_ROLES:
            os_name, os_family = _detect_os(ctx.disk_image_path, offset)

        tool, tool_reason = _suggest_tool(fs_type)

        # Im manuellen Modus: Analyst wählt Tool pro Partition
        if ctx.interactive_mode and fs_type in ANALYSABLE_FS and role not in SKIP_ROLES:
            tool = _ask_tool_selection(
                part['index'], fs_type, size_mb, tool, tool_reason,
                role=role, os_name=os_name, os_family=os_family,
                total=len(partitions)
            )
            tool_reason = f'{tool} (manuell gewählt)'

        entry = {
            'index':       part['index'],
            'offset':      offset,
            'size_mb':     size_mb,
            'fs_type':     fs_type,
            'role':        role,
            'os_name':     os_name,
            'os_family':   os_family,
            'tool':        tool,
            'tool_reason': tool_reason,
            'analysable':  fs_type in ANALYSABLE_FS and role not in SKIP_ROLES,
        }
        layout.append(entry)
        ctx.tool_selection[str(offset)] = tool
        log.info(f'  Partition {part["index"]}: offset={offset} fs={fs_type} role={role} os={os_name or "—"} tool={tool}')

    ctx.partition_layout    = layout
    ctx.analysis_partitions = [p for p in layout if p['analysable']]

    # Primäre Partition = größte ROOT/DATA-Partition
    root_parts = [p for p in layout if p['role'] == 'ROOT/DATA']
    if root_parts:
        ctx.primary_partition = max(root_parts, key=lambda p: p['size_mb'])

    # Multi-OS erkennen
    os_families = {p['os_family'] for p in layout if p['os_family']}
    ctx.multi_os_detected = len(os_families) > 1

    log.info(f'  {len(layout)} Partitionen, {len(ctx.analysis_partitions)} analysierbar, Multi-OS: {ctx.multi_os_detected}')
    if ctx.coc:
        ctx.coc.add_entry('stage_02', f'Partition-Layout: {len(layout)} Partitionen, {len(ctx.analysis_partitions)} analysierbar')
    return ctx


def _read_partitions(image_path: Path) -> List[dict]:
    partitions = []
    try:
        result = subprocess.run(
            [_tsk('mmls'), str(image_path)],
            capture_output=True, text=True, timeout=60
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].rstrip(':').isdigit():
                try:
                    partitions.append({
                        'index': int(parts[0].rstrip(':')),
                        'start': int(parts[2]),
                        'size':  int(parts[3]) if len(parts) > 3 else 0,
                    })
                except ValueError:
                    continue
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.warning(f'  mmls fehlgeschlagen: {e}')
    return partitions


def _detect_filesystem(image_path: Path, offset: int) -> str:
    try:
        result = subprocess.run(
            [_tsk('fsstat'), '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=30, errors='replace'
        )
        output = result.stdout.lower()
        for fs in ['ntfs', 'fat32', 'exfat', 'vfat', 'ext4', 'ext3', 'ext2', 'xfs', 'btrfs', 'swap']:
            if fs in output:
                return fs
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return 'unknown'


def _detect_role(fs_type: str, size_mb: float) -> str:
    if fs_type == 'swap':                                       return 'SWAP'
    if fs_type in ('vfat', 'fat16', 'fat32') and size_mb < 600: return 'BOOT'
    if size_mb < 50:                                            return 'UNBEKANNT'
    if fs_type in ('ext4', 'ext3', 'ext2', 'xfs', 'btrfs'):   return 'ROOT/DATA'
    if fs_type == 'ntfs':                                       return 'WINDOWS'
    return 'UNBEKANNT'


def _detect_os(image_path: Path, offset: int) -> tuple[str, str]:
    """Versucht OS via target-query zu erkennen — mit offset falls unterstützt."""
    try:
        result = subprocess.run(
            ['target-query', '-f', 'os', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        if not raw:
            return '', ''
        os_name   = raw
        os_family = _classify_os_family(raw.lower())
        return os_name, os_family
    except Exception:
        return '', ''


def _classify_os_family(raw: str) -> str:
    if any(kw in raw for kw in ('debian', 'ubuntu', 'kali', 'mint')):  return 'debian'
    if any(kw in raw for kw in ('rhel', 'centos', 'fedora', 'rocky', 'alma', 'red hat')): return 'rhel'
    if 'arch' in raw:   return 'arch'
    if 'alpine' in raw: return 'alpine'
    return ''


def _suggest_tool(fs_type: str) -> tuple[str, str]:
    preferred, reason = TOOL_POOL.get(fs_type, ('tsk', 'TSK — Fallback für unbekanntes Dateisystem'))
    if preferred != 'tsk' and not shutil.which(preferred):
        return 'tsk', f'TSK (Fallback — {preferred} nicht installiert ⚠️)'
    return preferred, reason


TOOL_DISPLAY = {
    'tsk':      ('⚡', 'TSK',     'ext4 · NTFS · FAT32'),
    'xfs_db':   ('🗄️', 'xfs_db', 'XFS Enterprise nativ'),
    'btrfs':    ('📦', 'btrfs',  'Btrfs Subvolumes nativ'),
    'debugfs':  ('🔬', 'debugfs','ext Tiefenanalyse'),
}

ROLE_ICON = {
    'ROOT/DATA': '💻',
    'BOOT':      '🥾',
    'SWAP':      '♻️',
    'WINDOWS':   '🪟',
    'UNBEKANNT': '❓',
}

OS_ICON = {
    'debian': '🐧',
    'rhel':   '🎩',
    'arch':   '🔵',
    'alpine': '🏔️',
}


def _ask_tool_selection(index: int, fs_type: str, size_mb: float,
                        suggestion: str, reason: str,
                        role: str = '', os_name: str = '',
                        os_family: str = '', total: int = 1) -> str:
    """Interaktive Tool-Auswahl im --mode manual — Variante C mit Rich."""
    from rich.console import Console
    from rich.table   import Table
    from rich        import box as rbox

    console = Console()
    all_tools   = [('tsk', True), ('xfs_db', bool(shutil.which('xfs_db'))),
                   ('btrfs', bool(shutil.which('btrfs'))), ('debugfs', bool(shutil.which('debugfs')))]
    role_icon = ROLE_ICON.get(role, '📂')
    os_icon   = OS_ICON.get(os_family, '🖥️')

    # ── Info-Block ────────────────────────────────────────────────────
    width = 56
    sep   = '─' * width
    print(f'\n  ┌{sep}┐')
    print(f'  │  🖴  Partition {index} von {total}{" " * (width - 18 - len(str(index)) - len(str(total)))}│')
    print(f'  │  ├─ Dateisystem:  {fs_type:<36}│')
    print(f'  │  ├─ Größe:        {size_mb:,.0f} MB{" " * (36 - len(f"{size_mb:,.0f} MB"))}│')
    print(f'  │  ├─ Rolle:        {role_icon} {role:<34}│')
    if os_name:
        os_line = f'{os_icon} {os_name}'
        print(f'  │  └─ OS erkannt:   {os_line:<35}│')
    else:
        print(f'  │  └─ OS erkannt:   {"—":<35}│')
    print(f'  ├{sep}┤')
    print(f'  │{" " * width}│')

    # ── Tool-Auswahl ─────────────────────────────────────────────────
    for i, (tool, available) in enumerate(all_tools, 1):
        icon, name, desc = TOOL_DISPLAY[tool]
        top_badge  = '  ✅ TOP' if tool == suggestion else ''
        avail_mark = '' if available else '  ⚠️ nicht installiert'
        line = f'{icon}  [{i}]  {name:<10}{desc}{top_badge}{avail_mark}'
        print(f'  │  {line:<{width - 2}}│')

    print(f'  │{" " * width}│')
    print(f'  └{sep}┘')

    # ── Eingabe ───────────────────────────────────────────────────────
    sugg_icon = TOOL_DISPLAY[suggestion][0]
    raw = input(f'         ↳ Enter für {sugg_icon} {suggestion}  oder  Zahl eingeben:  ').strip()

    tool_list = [t for t, _ in all_tools]
    if raw.isdigit() and 1 <= int(raw) <= len(tool_list):
        chosen = tool_list[int(raw) - 1]
        if not all_tools[int(raw) - 1][1]:
            print(f'  ⚠️  {chosen} nicht installiert — Fallback auf TSK')
            return 'tsk'
        return chosen
    return suggestion
