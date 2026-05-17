import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

OS_PROFILES = {
    'debian': {
        'keywords': ['debian', 'ubuntu', 'kali', 'mint'],
        'log_paths': {
            'syslog':  Path('/var/log/syslog'),
            'auth':    Path('/var/log/auth.log'),
            'kern':    Path('/var/log/kern.log'),
            'dpkg':    Path('/var/log/dpkg.log'),
            'daemon':  Path('/var/log/daemon.log'),
            'boot':    Path('/var/log/boot.log'),
            'ufw':     Path('/var/log/ufw.log'),
            'fail2ban':Path('/var/log/fail2ban.log'),
        },
    },
    'rhel': {
        'keywords': ['rhel', 'centos', 'fedora', 'red hat', 'rocky', 'alma'],
        'log_paths': {
            'syslog':  Path('/var/log/messages'),
            'auth':    Path('/var/log/secure'),
            'yum':     Path('/var/log/yum.log'),
            'dnf':     Path('/var/log/dnf.log'),
            'audit':   Path('/var/log/audit/audit.log'),
        },
    },
    'arch': {
        'keywords': ['arch'],
        'log_paths': {
            'pacman':  Path('/var/log/pacman.log'),
        },
    },
    'alpine': {
        'keywords': ['alpine'],
        'log_paths': {
            'syslog':  Path('/var/log/messages'),
            'auth':    Path('/var/log/auth.log'),
        },
    },
}


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 3: System-Profiling')
    os_release = _read_os_release(ctx.disk_image_path)

    for family, profile in OS_PROFILES.items():
        if any(kw in os_release.lower() for kw in profile['keywords']):
            ctx.os_family = family
            ctx.log_paths = profile['log_paths']
            break
    else:
        ctx.os_family = 'unknown'
        ctx.log_paths = _all_log_paths()

    ctx.os_name        = _extract_os_name(os_release) or ctx.os_family
    ctx.kernel_version = _read_kernel(ctx.disk_image_path)
    ctx.hostname       = _read_hostname(ctx.disk_image_path)
    ctx.timezone       = _read_timezone(ctx.disk_image_path)

    # Timezone dual-format: "Europe/Berlin (UTC+02:00)"
    ctx.timezone_display = _format_timezone_display(ctx.timezone)

    # Erweiterte Metadaten
    ctx.machine_id    = _read_field(ctx.disk_image_path, 'machine_id')
    ctx.ip_addresses  = _read_ip_addresses(ctx.disk_image_path)
    ctx.network_config= _read_field(ctx.disk_image_path, 'interfaces')

    # User-Profiling
    ctx.users, ctx.shadow_mtime, ctx.notable_users = _profile_users(ctx.disk_image_path)

    log.info(f'  OS: {ctx.os_name} ({ctx.os_family}), Kernel: {ctx.kernel_version}')
    log.info(f'  Hostname: {ctx.hostname}, TZ: {ctx.timezone_display}')
    log.info(f'  Nutzer: {len(ctx.users)} ({len(ctx.notable_users)} auffällig)')
    if ctx.coc:
        ctx.coc.add_entry('stage_03', f'Profiling: {ctx.os_name} | {len(ctx.users)} Nutzer')
    return ctx


def _parse_target_line(output: str) -> str:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if line.startswith('<Target ') and '>' in line:
            return line.split('>', 1)[-1].strip()
    return ''


def _read_os_release(image_path) -> str:
    if image_path is None:
        return ''
    try:
        result = subprocess.run(
            ['target-query', '-f', 'os', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.debug(f'target-query os stderr: {result.stderr.strip()}')
        raw = _parse_target_line(result.stdout) or result.stdout.strip()
        if raw and raw.lower() not in ('linux', 'unknown', ''):
            return raw
    except Exception as e:
        log.debug(f'target-query os fehlgeschlagen: {e}')
    log.debug('  OS-Erkennung: target-query zu generisch — TSK Fallback auf /etc/os-release')
    return _read_os_release_tsk(image_path)


def _read_os_release_tsk(image_path) -> str:
    """Liest /etc/os-release direkt via TSK fls+icat wenn target-query zu generisch ist."""
    mmls_cmd = shutil.which('mmls') or 'mmls'
    fls_cmd  = shutil.which('fls')  or 'fls'
    icat_cmd = shutil.which('icat') or 'icat'
    try:
        mmls_res = subprocess.run(
            [mmls_cmd, str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        offsets = []
        for line in mmls_res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].rstrip(':').isdigit():
                try:
                    offsets.append(int(parts[2]))
                except ValueError:
                    continue

        for offset in offsets:
            try:
                fls_res = subprocess.run(
                    [fls_cmd, '-r', '-p', '-o', str(offset), str(image_path)],
                    capture_output=True, text=True, timeout=45, errors='replace'
                )
                for line in fls_res.stdout.splitlines():
                    if 'etc/os-release' in line.lower() and '\t' in line:
                        # Format: "r/r [*] INODE:\tPATH"
                        meta  = line.split('\t')[0].strip()
                        inode = meta.split()[-1].rstrip(':')
                        icat_res = subprocess.run(
                            [icat_cmd, '-o', str(offset), str(image_path), inode],
                            capture_output=True, text=True, timeout=15, errors='replace'
                        )
                        if icat_res.returncode == 0 and 'NAME=' in icat_res.stdout:
                            log.debug(f'  /etc/os-release via TSK (offset={offset}, inode={inode})')
                            return icat_res.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
    except Exception as e:
        log.debug(f'TSK os-release Fallback fehlgeschlagen: {e}')
    return ''


def _extract_os_name(os_release: str) -> str:
    for line in os_release.splitlines():
        if line.startswith('PRETTY_NAME='):
            return line.split('=', 1)[1].strip().strip('"')
    if os_release.strip():
        return os_release.strip()
    return ''


def _read_kernel(image_path) -> str:
    try:
        result = subprocess.run(
            ['target-query', '-f', 'version', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.debug(f'target-query version stderr: {result.stderr.strip()}')
        val = _parse_target_line(result.stdout)
        return val if val else ''
    except Exception as e:
        log.debug(f'target-query version fehlgeschlagen: {e}')
        return ''


def _read_hostname(image_path) -> str:
    try:
        result = subprocess.run(
            ['target-query', '-f', 'hostname', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.debug(f'target-query hostname stderr: {result.stderr.strip()}')
        val = _parse_target_line(result.stdout)
        return val if val else result.stdout.strip() or 'unknown'
    except Exception as e:
        log.debug(f'target-query hostname fehlgeschlagen: {e}')
        return 'unknown'


def _read_timezone(image_path) -> str:
    try:
        result = subprocess.run(
            ['target-query', '-f', 'timezone', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            log.debug(f'target-query timezone stderr: {result.stderr.strip()}')
        val = _parse_target_line(result.stdout)
        tz = val if val else result.stdout.strip()
        return tz if tz else 'UTC'
    except Exception as e:
        log.debug(f'target-query timezone fehlgeschlagen: {e}')
        return 'UTC'


def _format_timezone_display(tz_name: str) -> str:
    """Gibt Timezone als 'Europe/Berlin (UTC+02:00)' zurück."""
    try:
        import pytz
        tz_obj    = pytz.timezone(tz_name)
        offset    = tz_obj.utcoffset(datetime.now())
        total_sec = int(offset.total_seconds())
        h         = abs(total_sec) // 3600
        m         = (abs(total_sec) % 3600) // 60
        sign      = '+' if total_sec >= 0 else '-'
        return f'{tz_name} (UTC{sign}{h:02d}:{m:02d})'
    except Exception:
        return tz_name


def _read_field(image_path, field: str) -> str:
    """Allgemeiner target-query Wrapper für einfache Felder."""
    if image_path is None:
        return ''
    try:
        result = subprocess.run(
            ['target-query', '-f', field, str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        val = _parse_target_line(result.stdout)
        return val if val else result.stdout.strip()
    except Exception as e:
        log.debug(f'target-query {field} fehlgeschlagen: {e}')
        return ''


def _read_ip_addresses(image_path) -> List[str]:
    """Liest IP-Adressen aus Netzwerkkonfiguration."""
    raw = _read_field(image_path, 'ips')
    if not raw:
        return []
    ips = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith('<'):
            ips.append(line)
    return ips[:10]  # max 10 IPs


def _profile_users(image_path) -> tuple[list, str, list]:
    """Liest Nutzer-Profil via target-query."""
    if image_path is None:
        return [], '', []
    users = []
    shadow_mtime = ''
    try:
        result = subprocess.run(
            ['target-query', '-f', 'users', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        users = _parse_users(raw)
    except Exception as e:
        log.debug(f'target-query users fehlgeschlagen: {e}')

    try:
        result = subprocess.run(
            ['target-query', '-f', 'stat', '/etc/shadow', str(image_path)],
            capture_output=True, text=True, timeout=15
        )
        shadow_mtime = _parse_target_line(result.stdout) or result.stdout.strip()
    except Exception:
        pass

    notable = [u['name'] for u in users
               if not u.get('is_system', True) and u.get('login_allowed', False)]
    return users, shadow_mtime, notable


def _parse_users(raw: str) -> list:
    """Parst target-query users Output."""
    users = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('<Target') or line.startswith('#'):
            continue
        # Format variiert je nach dissect-Version — robust parsen
        parts = line.split(':')
        if len(parts) >= 7:
            try:
                uid = int(parts[2]) if parts[2].isdigit() else -1
                users.append({
                    'name':          parts[0],
                    'uid':           uid,
                    'gid':           int(parts[3]) if parts[3].isdigit() else -1,
                    'home':          parts[5] if len(parts) > 5 else '',
                    'shell':         parts[6].strip() if len(parts) > 6 else '',
                    'login_allowed': parts[6].strip() not in ('/bin/false', '/usr/sbin/nologin', '') if len(parts) > 6 else False,
                    'is_system':     uid < 1000 and uid >= 0,
                    'has_password':  parts[1] not in ('', 'x', '*', '!') if len(parts) > 1 else False,
                })
            except (ValueError, IndexError):
                continue
    return users


def _all_log_paths() -> dict:
    return {
        'syslog':  Path('/var/log/syslog'),
        'auth':    Path('/var/log/auth.log'),
        'kern':    Path('/var/log/kern.log'),
        'messages':Path('/var/log/messages'),
        'secure':  Path('/var/log/secure'),
    }
