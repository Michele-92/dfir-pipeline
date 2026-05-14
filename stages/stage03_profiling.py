import logging
import subprocess
from pathlib import Path

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

    ctx.os_name       = _extract_os_name(os_release) or ctx.os_family
    ctx.kernel_version = _read_kernel(ctx.disk_image_path)
    ctx.hostname      = _read_hostname(ctx.disk_image_path)
    ctx.timezone      = _read_timezone(ctx.disk_image_path)

    log.info(f'  OS: {ctx.os_name} ({ctx.os_family}), Kernel: {ctx.kernel_version}')
    log.info(f'  Hostname: {ctx.hostname}, TZ: {ctx.timezone}')
    if ctx.coc:
        ctx.coc.add_entry('stage_03', f'Profiling: {ctx.os_name}')
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
        return _parse_target_line(result.stdout) or result.stdout.strip()
    except Exception as e:
        log.debug(f'target-query os fehlgeschlagen: {e}')
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


def _all_log_paths() -> dict:
    return {
        'syslog':  Path('/var/log/syslog'),
        'auth':    Path('/var/log/auth.log'),
        'kern':    Path('/var/log/kern.log'),
        'messages':Path('/var/log/messages'),
        'secure':  Path('/var/log/secure'),
    }
