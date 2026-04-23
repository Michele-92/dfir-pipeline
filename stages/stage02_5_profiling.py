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
    log.info('Stage 2.5: System-Profiling')
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
        ctx.coc.add_entry('stage_02_5', f'Profiling: {ctx.os_name}')
    return ctx


def _read_os_release(image_path) -> str:
    if image_path is None:
        return ''
    try:
        result = subprocess.run(
            ['target-query', '-t', str(image_path), 'cat', '/etc/os-release'],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout
    except Exception:
        return ''


def _extract_os_name(os_release: str) -> str:
    for line in os_release.splitlines():
        if line.startswith('PRETTY_NAME='):
            return line.split('=', 1)[1].strip().strip('"')
    return ''


def _read_kernel(image_path) -> str:
    try:
        result = subprocess.run(
            ['target-query', '-t', str(image_path), 'cat', '/proc/version'],
            capture_output=True, text=True, timeout=30
        )
        parts = result.stdout.split()
        return parts[2] if len(parts) > 2 else ''
    except Exception:
        return ''


def _read_hostname(image_path) -> str:
    try:
        result = subprocess.run(
            ['target-query', '-t', str(image_path), 'cat', '/etc/hostname'],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except Exception:
        return 'unknown'


def _read_timezone(image_path) -> str:
    try:
        result = subprocess.run(
            ['target-query', '-t', str(image_path), 'cat', '/etc/timezone'],
            capture_output=True, text=True, timeout=30
        )
        tz = result.stdout.strip()
        return tz if tz else 'UTC'
    except Exception:
        return 'UTC'


def _all_log_paths() -> dict:
    return {
        'syslog':  Path('/var/log/syslog'),
        'auth':    Path('/var/log/auth.log'),
        'kern':    Path('/var/log/kern.log'),
        'messages':Path('/var/log/messages'),
        'secure':  Path('/var/log/secure'),
    }
