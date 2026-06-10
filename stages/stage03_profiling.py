import logging
import re
import shutil
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Dict

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


KNOWN_SYSTEM_USERS = {
    'debian': {
        'root','daemon','bin','sys','sync','games','man','lp','mail','news','uucp',
        'proxy','www-data','backup','list','irc','gnats','nobody','systemd-network',
        'systemd-resolve','systemd-timesync','messagebus','syslog','_apt','tss',
        'uuidd','tcpdump','landscape','pollinate','sshd','postfix','avahi',
        'cups-pk-helper','rtkit','dnsmasq','colord','gdm','pulse',
    },
    'rhel': {
        'root','bin','daemon','adm','lp','sync','shutdown','halt','mail','operator',
        'games','ftp','nobody','dbus','polkitd','rpc','rpcuser','nfsnobody','sshd',
        'postfix','chrony','systemd-network','systemd-bus-proxy','tss','sssd',
        'unbound','gluster','saslauth','rpcbind',
    },
    'alpine': {
        'root','bin','daemon','adm','lp','sync','shutdown','halt','mail','news',
        'uucp','operator','man','postmaster','cron','ftp','sshd','at','squid',
        'xfs','games','cyrus','vpopmail','ntp','smmsp','guest','nobody',
        'apache','nginx','postgres','mysql','redis',
    },
    'arch': {
        'root','bin','daemon','mail','ftp','http','uuidd','dbus','nobody',
        'systemd-journal-remote','systemd-network','systemd-resolve',
        'systemd-timesync','systemd-coredump','polkitd','rtkit','avahi',
        'colord','gdm','sddm','lightdm',
    },
}


# Standard-Services je OS-Familie — Services die NICHT in dieser Liste stehen
# werden als "non-standard" markiert (möglicher forensischer Hinweis).
STANDARD_SERVICES: Dict[str, set] = {
    'debian': {
        # systemd Kern-Services
        'systemd-journald', 'systemd-logind', 'systemd-networkd', 'systemd-resolved',
        'systemd-timesyncd', 'systemd-udevd', 'systemd-tmpfiles-setup',
        'systemd-tmpfiles-clean', 'systemd-update-utmp', 'systemd-modules-load',
        'systemd-sysctl', 'systemd-remount-fs', 'systemd-fsck-root', 'systemd-fsck',
        'systemd-quotacheck', 'systemd-random-seed', 'systemd-backlight',
        'systemd-rfkill', 'systemd-ask-password-wall', 'systemd-ask-password-console',
        'systemd-machine-id-commit', 'systemd-journal-flush', 'systemd-journal-catalog',
        # Netzwerk
        'networking', 'network-manager', 'NetworkManager', 'networkd-dispatcher',
        'ifupdown', 'resolvconf', 'isc-dhcp-client', 'isc-dhcp-server',
        # SSH
        'ssh', 'sshd', 'openssh-server',
        # Logging
        'rsyslog', 'syslog', 'syslogd', 'klogd',
        # Cron
        'cron', 'crond', 'anacron', 'at',
        # Paketmanagement Debian/Ubuntu
        'apt-daily', 'apt-daily-upgrade', 'unattended-upgrades',
        'packagekit', 'dpkg',
        # Systemdienste
        'dbus', 'polkit', 'udev', 'acpid', 'apmd', 'upower',
        'accounts-daemon', 'avahi-daemon', 'bluetooth',
        'cups', 'cups-browsed', 'colord',
        'pcscd', 'rtkit-daemon', 'udisks2',
        'thermald', 'irqbalance', 'fwupd', 'fwupd-refresh',
        'console-setup', 'keyboard-setup', 'setvtrgb',
        'plymouth', 'plymouth-quit', 'plymouth-read-write',
        # Boot / Init
        'e2scrub_reap', 'e2scrub_all', 'fstrim',
        # Cloud / VM
        'cloud-init', 'cloud-init-local', 'cloud-final', 'cloud-config',
        'open-vm-tools', 'vmware-tools', 'qemu-guest-agent',
        'amazon-ssm-agent', 'amazon-cloudwatch-agent',
        'google-startup-scripts', 'google-shutdown-scripts',
        # Zeitdienste
        'ntp', 'ntpd', 'chrony', 'chronyd', 'timesyncd',
        # Diverse (Ubuntu-spezifisch)
        'snapd', 'snap', 'multipathd', 'apport', 'whoopsie',
        'ModemManager', 'wpa-supplicant', 'wpa_supplicant',
    },
    'rhel': {
        # systemd Kern-Services
        'systemd-journald', 'systemd-logind', 'systemd-networkd', 'systemd-resolved',
        'systemd-timesyncd', 'systemd-udevd', 'systemd-tmpfiles-setup',
        'systemd-tmpfiles-clean', 'systemd-update-utmp', 'systemd-modules-load',
        'systemd-sysctl', 'systemd-remount-fs', 'systemd-random-seed',
        # Netzwerk
        'NetworkManager', 'network', 'firewalld', 'iptables', 'ip6tables',
        'networkd-dispatcher',
        # SSH
        'sshd',
        # Logging / Audit
        'rsyslog', 'auditd',
        # Cron
        'crond', 'anacron', 'atd',
        # Paketmanagement RHEL/CentOS
        'yum-cron', 'dnf-makecache', 'packagekit',
        # Systemdienste
        'dbus', 'polkit', 'tuned', 'irqbalance', 'acpid',
        'chronyd', 'ntpd', 'ntp', 'timesyncd',
        'accounts-daemon', 'rtkit-daemon', 'udisks2', 'upower',
        # Storage
        'lvm2-monitor', 'dm-event', 'multipathd', 'mdadm',
        'rpcbind', 'rpc-statd', 'nfs-server', 'nfs-client',
        # SELinux
        'selinux-autorelabel',
        # Cloud / VM
        'cloud-init', 'cloud-init-local', 'cloud-final', 'cloud-config',
        'open-vm-tools', 'amazon-ssm-agent', 'amazon-cloudwatch-agent',
        # Boot
        'plymouth', 'plymouth-quit', 'plymouth-read-write',
        # Zeitdienste
        'chrony', 'chronyd',
    },
    'alpine': {
        # Alpine nutzt OpenRC — meist keine .service Dateien im systemd-Format
        'sshd', 'networking', 'crond', 'syslog', 'klogd',
        'udev', 'mdev', 'dbus', 'acpid', 'ntpd', 'chronyd',
        'openrc', 'local', 'bootmisc', 'hostname', 'modules',
        'mount-ro', 'sysfs', 'devfs', 'procfs', 'loopback',
    },
    'arch': {
        # systemd Kern-Services
        'systemd-journald', 'systemd-logind', 'systemd-networkd', 'systemd-resolved',
        'systemd-timesyncd', 'systemd-udevd', 'systemd-tmpfiles-setup',
        'systemd-tmpfiles-clean', 'systemd-update-utmp', 'systemd-modules-load',
        # Netzwerk
        'NetworkManager', 'dhcpcd', 'netctl', 'networkd-dispatcher',
        # SSH
        'sshd',
        # Logging
        'rsyslog', 'syslog-ng',
        # Cron
        'cronie', 'fcron', 'at',
        # Paketmanagement Arch
        'pacman', 'reflector',
        # Systemdienste
        'dbus', 'polkit', 'acpid', 'upower', 'udisks2',
        'avahi-daemon', 'bluetooth', 'cups',
        'rtkit-daemon', 'colord',
        'irqbalance', 'fwupd',
        # Zeitdienste
        'ntpd', 'chronyd', 'timesyncd',
        # Cloud / VM
        'cloud-init', 'open-vm-tools', 'qemu-guest-agent',
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

    # User-Profiling — Primärquelle: target-query (ganzes Image)
    ctx.users, ctx.shadow_mtime, ctx.notable_users, ctx.unexpected_users = \
        _profile_users(ctx.disk_image_path, ctx.os_family)

    # ── Per-Partition Profiling ───────────────────────────────────────
    primary_offset = ctx.primary_partition.get('offset') if ctx.primary_partition else None

    _primary_index = get_partition_index(ctx.disk_image_path, primary_offset) if primary_offset else {}

    # ── Review-Fix HIGH #11: OS-Prioritaetsmodell als Rettungsanker ──
    # Greift wenn target-query/os-release-Erstfund versagt haben
    # (os_family 'unknown' oder kein brauchbarer Name).
    if primary_offset is not None and (
            ctx.os_family in ('', 'unknown')
            or not ctx.os_name or ctx.os_name in ('unknown', ctx.os_family)):
        _os = detect_os_from_partition(ctx.disk_image_path, primary_offset,
                                       _primary_index)
        if _os['os_name']:
            log.info(f"  OS-Kaskade: {_os['os_name']} "
                     f"(Familie: {_os['os_family'] or '?'}) [{_os['source']}]")
            ctx.os_name = _os['os_name']
            if _os['os_family'] and _os['os_family'] in OS_PROFILES:
                ctx.os_family = _os['os_family']
                ctx.log_paths = OS_PROFILES[_os['os_family']]['log_paths']
            elif _os['os_family']:
                ctx.os_family = _os['os_family']   # z.B. 'suse' — Log-Pfade bleiben generisch

    # ── Review-Fix HIGH #9: Shadow-mtime via istat auch fuer die primaere
    # Partition (der fruehere target-query-'-f stat'-Aufruf war fehlerhaft —
    # /etc/shadow wurde als Target interpretiert -> Ergebnis fast immer leer)
    if not ctx.shadow_mtime and primary_offset is not None and 'etc/shadow' in _primary_index:
        ctx.shadow_mtime = _read_shadow_mtime_tsk(
            ctx.disk_image_path, primary_offset, _primary_index['etc/shadow'])
        if ctx.shadow_mtime:
            log.info(f'  Shadow-mtime via istat: {ctx.shadow_mtime}')

    # ── Review-Fix HIGH #10: Machine-ID — target-query liefert fuer Linux-
    # Targets meist nichts; Fallback-Kette via icat (inkl. dbus-Pfad).
    # Plausibilitaet: machine-id ist immer 32 Hex-Zeichen.
    if ctx.machine_id and not re.fullmatch(r'[0-9a-f]{32}', ctx.machine_id.strip()):
        ctx.machine_id = ''
    if not ctx.machine_id and primary_offset is not None:
        for _mid_path in ('etc/machine-id', 'var/lib/dbus/machine-id'):
            if _mid_path in _primary_index:
                _raw = _read_icat(ctx.disk_image_path, primary_offset,
                                  _primary_index[_mid_path]).strip()
                if re.fullmatch(r'[0-9a-f]{32}', _raw):
                    ctx.machine_id = _raw
                    log.info(f'  Machine-ID via TSK ({_mid_path}): {_raw}')
                    break

    # TSK-Fallback für Nutzer: falls target-query keinen regulären User (UID ≥ 1000) liefert,
    # /etc/passwd direkt via TSK/icat lesen. Bedingung: KEIN User mit UID ≥ 1000 vorhanden
    # (nicht nur komplett leere Liste — target-query kann root parsen aber UID-1000-User verpassen).
    _has_regular_user = any(u.get('uid', -1) >= 1000 for u in ctx.users)
    if not _has_regular_user and 'etc/passwd' in _primary_index and primary_offset is not None:
        log.info('  Nutzer-Fallback: target-query leer → lese /etc/passwd via TSK')
        raw_passwd = _read_icat(ctx.disk_image_path, primary_offset,
                                _primary_index['etc/passwd'])
        if raw_passwd:
            ctx.users = _parse_users(raw_passwd, ctx.os_family)
            creation_times = _read_user_creation_times(
                ctx.disk_image_path, primary_offset, _primary_index
            )
            for u in ctx.users:
                u['created_at'] = creation_times.get(u['name'], '')
            ctx.notable_users   = [u['name'] for u in ctx.users
                                   if not u.get('is_system', True)
                                   and u.get('login_allowed', False)]
            ctx.unexpected_users = [u['name'] for u in ctx.users
                                    if u.get('is_unexpected', False)]
            log.info(f'  TSK-Fallback: {len(ctx.users)} Nutzer aus /etc/passwd gelesen')
    primary_profile = {
        'is_primary':       True,
        'partition_index':  ctx.primary_partition.get('index', '?') if ctx.primary_partition else '?',
        'size_mb':          ctx.primary_partition.get('size_mb', 0)  if ctx.primary_partition else 0,
        'fs_type':          ctx.primary_partition.get('fs_type', '')  if ctx.primary_partition else '',
        'offset':           primary_offset or 0,
        'os_name':          ctx.os_name,
        'os_family':        ctx.os_family,
        'hostname':         ctx.hostname,
        'timezone':         ctx.timezone,
        'timezone_display': ctx.timezone_display,
        'kernel_version':   ctx.kernel_version,
        'machine_id':       ctx.machine_id,
        'ip_addresses':     ctx.ip_addresses,
        'users':            ctx.users,
        'notable_users':    ctx.notable_users,
        'unexpected_users': ctx.unexpected_users,
        'shadow_mtime':     ctx.shadow_mtime,
        'install_time':     _read_install_time(
            ctx.disk_image_path, primary_offset or 0, _primary_index, ctx.os_family
        ),
        'sudo_users':     _read_sudo_rights(ctx.disk_image_path, primary_offset or 0, _primary_index),
        'groups_map':     _read_group_memberships(ctx.disk_image_path, primary_offset or 0, _primary_index),
        'packages':       _read_installed_packages(ctx.disk_image_path, primary_offset or 0, _primary_index, ctx.os_family),
        'services':       _read_enabled_services(_primary_index, ctx.os_family),
        'ssh_config':     _read_ssh_config(ctx.disk_image_path, primary_offset or 0, _primary_index),
        'virtualization': _detect_virtualization(_primary_index),
        'usage_period':   _read_usage_period(ctx.disk_image_path, primary_offset or 0, _primary_index, ctx.os_family),
        'net_config':     _read_network_config_structured(ctx.disk_image_path, primary_offset or 0, _primary_index, ctx.os_family),
    }

    # ── Anti-Forensik-Rohdaten extrahieren ───────────────────────────────
    _all_kernels    = _read_all_kernels(_primary_index)
    _primary_grub   = _read_grub_config(ctx.disk_image_path, primary_offset or 0, _primary_index)
    _compile_flags  = _read_kernel_compile_flags(
        ctx.disk_image_path, primary_offset or 0, _primary_index, _all_kernels
    )
    _swap           = _read_swap_config(ctx.disk_image_path, primary_offset or 0, _primary_index)
    _rc_local       = _read_rc_local(
        ctx.disk_image_path, primary_offset or 0, _primary_index, ctx.os_family
    )
    _reboot_pending = _check_reboot_pending(_primary_index, ctx.os_family)
    _loaded_kernel  = _read_loaded_kernel_from_logs(
        ctx.disk_image_path, primary_offset or 0, _primary_index, ctx.os_family
    )
    _symlinks       = _index_symlinks(ctx.disk_image_path, primary_offset or 0)

    # In ctx speichern
    ctx.all_kernel_versions     = _all_kernels
    ctx.grub_config             = _primary_grub
    ctx.kernel_compile_flags    = _compile_flags
    ctx.swap_config             = _swap
    ctx.rc_local_content        = _rc_local
    ctx.reboot_pending          = _reboot_pending
    ctx.loaded_kernel_from_logs = _loaded_kernel
    ctx.primary_symlinks        = _symlinks

    # ── Bug-Fix: Kernel-Version validieren ───────────────────────────────────
    # target-query -f version kann den OS-Namen zurückgeben ("Ubuntu 20.04.5 LTS")
    # statt der Kernel-Version ("5.15.0-1031-aws"). Eine echte Kernel-Version
    # beginnt immer mit Ziffern und Punkten (z.B. 5.15.0, 6.1.0-21).
    if ctx.kernel_version and not re.search(r'^\d+\.\d+', ctx.kernel_version):
        _k_fix = ''
        if _all_kernels:
            _k_fix = _all_kernels[0]
        elif _primary_grub.get('active_kernel'):
            _k_fix = _primary_grub['active_kernel']
        if _k_fix:
            log.debug(
                f'  Kernel-Fix: target-query gab "{ctx.kernel_version}" '
                f'(sieht wie OS-Name aus) → override mit "{_k_fix}" aus /boot/vmlinuz-*'
            )
            ctx.kernel_version = _k_fix

    # primary_profile mit ggf. korrigierter Kernel-Version synchronisieren
    primary_profile['kernel_version'] = ctx.kernel_version

    # In primary_profile eintragen (fuer Report-Builder)
    primary_profile['all_kernels']          = _all_kernels
    primary_profile['grub_config']          = _primary_grub
    primary_profile['kernel_compile_flags'] = _compile_flags
    primary_profile['swap_config']          = _swap
    primary_profile['rc_local_content']     = _rc_local
    primary_profile['reboot_pending']       = _reboot_pending
    primary_profile['loaded_kernel']        = _loaded_kernel

    # Primäre User anreichern
    _primary_last  = _read_last_logins(ctx.disk_image_path, primary_offset or 0, _primary_index)
    _primary_meth  = _read_login_methods(ctx.disk_image_path, primary_offset or 0, _primary_index)
    for u in primary_profile['users']:
        uid_e = _primary_last.get(u['uid'], {})
        u['last_login_time']  = uid_e.get('time', '')
        u['last_login_host']  = uid_e.get('host', '')
        u['login_methods']    = _primary_meth.get(u['name'], [])
        u['groups']           = primary_profile['groups_map'].get(u['name'], [])
        u['has_sudo']         = (u['name'] in primary_profile['sudo_users'] or
                                 any(f'%{g}' in primary_profile['sudo_users']
                                     for g in u.get('groups', [])))
        home = u.get('home', '').lstrip('/')
        u['shell_histories']  = [
            h for h in ('bash', 'zsh', 'fish')
            if f"{home}/.{h}_history" in _primary_index or
               (u['name'] == 'root' and f"root/.{h}_history" in _primary_index)
        ]
    partition_profiles = [primary_profile]

    secondary = sorted(
        [p for p in ctx.analysis_partitions if p.get('offset') != primary_offset],
        key=lambda x: x['size_mb'], reverse=True
    )
    for p in secondary:
        log.info(f'  Profiling Partition {p["index"]} (offset={p["offset"]}) via TSK...')
        prof = _profile_partition_tsk(ctx.disk_image_path, p['offset'])
        prof.update({
            'is_primary':      False,
            'partition_index': p['index'],
            'size_mb':         p['size_mb'],
            'fs_type':         p['fs_type'],
            'offset':          p['offset'],
            'ip_addresses':    [],
        })
        partition_profiles.append(prof)

    ctx.partition_profiles = partition_profiles

    log.info(f'  OS: {ctx.os_name} ({ctx.os_family}), Kernel: {ctx.kernel_version}')
    log.info(f'  Hostname: {ctx.hostname}, TZ: {ctx.timezone_display}')
    log.info(f'  Nutzer: {len(ctx.users)} ({len(ctx.notable_users)} auffällig)')
    log.info(f'  Partition-Profile: {len(partition_profiles)} erstellt')
    if ctx.coc:
        ctx.coc.add_entry('stage_03', f'Profiling: {ctx.os_name} | {len(ctx.users)} Nutzer | {len(partition_profiles)} Partitionen')
    return ctx


def _parse_target_line(output: str) -> str:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if line.startswith('<Target ') and '>' in line:
            return line.split('>', 1)[-1].strip()
    return ''


def _index_partition(image_path: Path, offset: int) -> dict:
    """Erstellt Datei-Index {path → inode} einer Partition via fls -r -p."""
    fls_cmd = shutil.which('fls') or 'fls'
    index   = {}
    try:
        # Timeout 600s (Review-Fix #12): bei grossen Partitionen lief fls
        # laenger als die frueheren 60s -> leerer Index -> komplettes
        # Sekundaer-Profil zeigte 'Unbekannt'. Stage 05 nutzt ebenfalls 300-600s.
        res = subprocess.run(
            [fls_cmd, '-r', '-p', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=600, errors='replace'
        )
        for line in res.stdout.splitlines():
            if '\t' not in line:
                continue
            meta, path = line.split('\t', 1)
            parts = meta.strip().split()
            inode = parts[-1].rstrip(':')
            # removeprefix statt lstrip('./') — lstrip frass ALLE fuehrenden
            # Punkte/Slashes und machte '.dockerenv' zu 'dockerenv'
            # (Virtualisierungserkennung Docker/LXC war dadurch tot)
            path_norm = path.strip().removeprefix('./').lower()
            index[path_norm] = inode
    except Exception as e:
        log.debug(f'  fls Index fehlgeschlagen (offset={offset}): {e}')
    return index


# ── Partition-Index-Cache ────────────────────────────────────────────────
# Stage 02 (OS-Erkennung) und Stage 03 (Profiling) brauchen denselben
# fls-Index — der Cache stellt sicher, dass fls pro Partition nur EINMAL
# laeuft (fls -r -p kann auf grossen Partitionen Minuten dauern).
_INDEX_CACHE: Dict[tuple, dict] = {}


def get_partition_index(image_path: Path, offset: int) -> dict:
    key = (str(image_path), int(offset))
    if key not in _INDEX_CACHE:
        _INDEX_CACHE[key] = _index_partition(image_path, offset)
    return _INDEX_CACHE[key]


# ── OS-Prioritaetsmodell (Review-Fix HIGH #11) ───────────────────────────
# Erkennungs-Kaskade PRO PARTITION, verlaesslichste Quelle zuerst.
# Liefert immer auch die Quelle ('source') — nachpruefbare Provenienz.

_OS_RELEASE_PATHS = ('etc/os-release', 'usr/lib/os-release')

# (pfad_im_index, familie, name_template oder None=Dateiinhalt ist der Name)
_DISTRO_FILES = (
    ('etc/debian_version', 'debian', 'Debian {v}'),
    ('etc/redhat-release', 'rhel',   None),
    ('etc/centos-release', 'rhel',   None),
    ('etc/fedora-release', 'rhel',   None),
    ('etc/alpine-release', 'alpine', 'Alpine Linux {v}'),
    ('etc/arch-release',   'arch',   'Arch Linux'),
    ('etc/suse-release',   'suse',   None),   # Index-Keys sind lowercase
)

# (index-praefix, familie, beschreibung) — schwaechste Stufe: Heuristik
_PKG_HEURISTICS = (
    ('var/lib/dpkg/status',   'debian', 'Debian-Familie (dpkg-Datenbank vorhanden)'),
    ('var/lib/rpm/',          'rhel',   'RHEL-Familie (rpm-Datenbank vorhanden)'),
    ('lib/apk/db/installed',  'alpine', 'Alpine (apk-Datenbank vorhanden)'),
    ('var/lib/pacman/',       'arch',   'Arch (pacman-Datenbank vorhanden)'),
)


def detect_os_from_partition(image_path: Path, offset: int,
                             index: dict = None, _read=None) -> dict:
    """Erkennt das OS EINER Partition ueber eine Prioritaeten-Kaskade.

    Prioritaet:
      1. etc/os-release          (Standard)
      2. usr/lib/os-release      (Backup-Kopie)
      3. Distro-Releasedateien   (debian_version, redhat-release, ...)
      4. etc/issue               (Login-Banner)
      5. Paketmanager-Heuristik  (dpkg/rpm/apk/pacman-Datenbank)

    Rueckgabe: {'os_name', 'os_family', 'source'} — leere Strings wenn
    nichts erkannt wurde. 'source' dokumentiert die Gewinner-Quelle.
    _read ist injizierbar (Tests ohne TSK/Subprozesse).
    """
    if index is None:
        index = get_partition_index(image_path, offset)
    if _read is None:
        _read = _read_icat
    if not index:
        return {'os_name': '', 'os_family': '', 'source': ''}

    # Stufe 1+2: os-release
    for rel_path in _OS_RELEASE_PATHS:
        if rel_path not in index:
            continue
        content = _read(image_path, offset, index[rel_path])
        if content and 'NAME=' in content:
            name   = _extract_os_name(content)
            family = _classify_os_family_from_content(content)
            if name:
                return {'os_name': name,
                        'os_family': family if family != 'unknown' else '',
                        'source': '/' + rel_path}

    # Stufe 3: Distro-Releasedateien
    for rel_path, family, template in _DISTRO_FILES:
        if rel_path not in index:
            continue
        content = _read(image_path, offset, index[rel_path]).strip()
        first_line = content.splitlines()[0].strip() if content else ''
        if template is None:
            name = first_line
        else:
            name = template.format(v=first_line).strip()
        if name:
            return {'os_name': name, 'os_family': family,
                    'source': '/' + rel_path}

    # Stufe 4: /etc/issue (Banner — getty-Escapes wie \n \l entfernen)
    if 'etc/issue' in index:
        content = _read(image_path, offset, index['etc/issue'])
        if content:
            first = content.splitlines()[0] if content.splitlines() else ''
            clean = re.sub(r'\\[a-zA-Z]', '', first).strip()
            family = _classify_os_family_from_content(clean)
            if clean and family != 'unknown':
                return {'os_name': clean, 'os_family': family,
                        'source': '/etc/issue'}

    # Stufe 5: Paketmanager-Heuristik (nur Familie, kein exakter Name)
    for prefix, family, desc in _PKG_HEURISTICS:
        if prefix.endswith('/'):
            found = any(k.startswith(prefix) for k in index)
        else:
            found = prefix in index
        if found:
            return {'os_name': desc, 'os_family': family,
                    'source': f'Heuristik: {prefix}'}

    return {'os_name': '', 'os_family': '', 'source': ''}


def _read_icat(image_path: Path, offset: int, inode: str) -> str:
    """Liest Datei-Inhalt via icat."""
    icat_cmd = shutil.which('icat') or 'icat'
    try:
        res = subprocess.run(
            [icat_cmd, '-o', str(offset), str(image_path), inode],
            capture_output=True, text=True, timeout=15, errors='replace'
        )
        if res.returncode == 0:
            return res.stdout
    except Exception:
        pass
    return ''


def _read_shadow_mtime_tsk(image_path: Path, offset: int, inode: str) -> str:
    """Liest Modifikationszeit einer Datei via istat.

    Unterstützt beide TSK-Ausgabeformate:
      Alte TSK: 'Modified:       Thu Mar 12 00:17:01 2020'  (Wert auf gleicher Zeile)
      Neue TSK: 'Modified:'  + nächste Zeile: '2020-03-12 00:17:01 (UTC)'
    """
    istat_cmd = shutil.which('istat') or 'istat'
    try:
        res = subprocess.run(
            [istat_cmd, '-o', str(offset), str(image_path), inode],
            capture_output=True, text=True, timeout=10, errors='replace'
        )
        lines = res.stdout.splitlines()
        for i, line in enumerate(lines):
            if line.strip().lower().startswith('modified:'):
                value = line.split(':', 1)[1].strip()
                if value:
                    return value                      # altes Format: Wert auf gleicher Zeile
                elif i + 1 < len(lines):
                    return lines[i + 1].strip()       # neues Format: Wert auf nächster Zeile
    except Exception:
        pass
    return ''


def _classify_os_family_from_content(content: str) -> str:
    """Klassifiziert OS-Familie aus /etc/os-release Inhalt."""
    c = content.lower()
    if any(kw in c for kw in ('debian', 'ubuntu', 'kali', 'mint')):   return 'debian'
    if any(kw in c for kw in ('rhel', 'centos', 'fedora', 'rocky', 'alma', 'red hat')): return 'rhel'
    if any(kw in c for kw in ('suse', 'sles', 'opensuse')): return 'suse'
    if 'arch'   in c: return 'arch'
    if 'alpine' in c: return 'alpine'
    return 'unknown'


def _read_icat_binary(image_path: Path, offset: int, inode: str) -> bytes:
    """Liest Datei-Inhalt als Bytes via icat — für Binärdateien (lastlog, wtmp)."""
    icat_cmd = shutil.which('icat') or 'icat'
    try:
        res = subprocess.run(
            [icat_cmd, '-o', str(offset), str(image_path), inode],
            capture_output=True, timeout=15
        )
        if res.returncode == 0:
            return res.stdout
    except Exception:
        pass
    return b''


def _read_last_logins(image_path: Path, offset: int, index: dict) -> dict:
    """Liest letzten Login pro User aus /var/log/lastlog (binär, 292 Bytes/UID)."""
    LASTLOG_SIZE   = 292
    LASTLOG_STRUCT = struct.Struct('<l32s256s')
    result = {}
    if 'var/log/lastlog' not in index:
        return result
    data = _read_icat_binary(image_path, offset, index['var/log/lastlog'])
    if not data:
        return result
    for uid in range(len(data) // LASTLOG_SIZE):
        start = uid * LASTLOG_SIZE
        chunk = data[start:start + LASTLOG_SIZE]
        if len(chunk) < LASTLOG_SIZE:
            break
        try:
            ts_sec, _, host = LASTLOG_STRUCT.unpack(chunk)
            if ts_sec > 0:
                result[uid] = {
                    'time': datetime.utcfromtimestamp(ts_sec).strftime('%Y-%m-%d %H:%M UTC'),
                    'host': host.rstrip(b'\x00').decode('utf-8', errors='replace').strip(),
                }
        except Exception:
            continue
    return result


def _read_login_methods(image_path: Path, offset: int, index: dict) -> dict:
    """Erkennt Login-Methoden pro User aus wtmp (binary) + auth.log (text)."""
    methods: dict = {}

    # Quelle 1: wtmp — Session-Typ erkennen
    # Linux utmp/wtmp x86-64: 384 Bytes, Felder per direktem Byte-Offset
    # ut_type(0,2) | padding(2) | ut_pid(4,4) | ut_line(8,32) | ut_id(40,4)
    # ut_user(44,32) | ut_host(76,256) | ...
    WTMP_SIZE = 384
    for wtmp_path in ('var/log/wtmp',):
        if wtmp_path not in index:
            continue
        data = _read_icat_binary(image_path, offset, index[wtmp_path])
        if not data:
            continue
        # Stride automatisch ermitteln (384 oder 392 je nach Architektur)
        for stride in (384, 392):
            if len(data) % stride == 0 and len(data) >= stride:
                WTMP_SIZE = stride
                break
        for i in range(len(data) // WTMP_SIZE):
            chunk = data[i * WTMP_SIZE:(i + 1) * WTMP_SIZE]
            if len(chunk) < WTMP_SIZE:
                break
            try:
                ut_type = struct.unpack_from('<h', chunk, 0)[0]
                if ut_type != 7:  # USER_PROCESS
                    continue
                ut_line = chunk[8:40].rstrip(b'\x00').decode('utf-8', errors='replace').strip()
                ut_user = chunk[44:76].rstrip(b'\x00').decode('utf-8', errors='replace').strip()
                ut_host = chunk[76:332].rstrip(b'\x00').decode('utf-8', errors='replace').strip()
                if not ut_user:
                    continue
                s = methods.setdefault(ut_user, set())
                if ut_host:
                    s.add('ssh_remote')
                elif ut_line.startswith('pts/'):
                    s.add('ssh_local')
                elif ut_line.startswith('tty'):
                    s.add('console')
            except Exception:
                continue

    # Quelle 2: auth.log — SSH-Methode (Key vs. Passwort)
    for auth_path in ('var/log/auth.log', 'var/log/secure'):
        if auth_path not in index:
            continue
        content = _read_icat(image_path, offset, index[auth_path])
        for m in re.finditer(r'Accepted (password|publickey) for (\S+)', content):
            method, user = m.group(1), m.group(2)
            s = methods.setdefault(user, set())
            s.add('ssh_key' if method == 'publickey' else 'ssh_password')
        break

    return {u: list(s) for u, s in methods.items()}


def _read_sudo_rights(image_path: Path, offset: int, index: dict) -> list:
    """Liest Sudo-Rechte aus /etc/sudoers und /etc/sudoers.d/*."""
    sudo_entries = []
    files_to_check = [k for k in index if k == 'etc/sudoers' or k.startswith('etc/sudoers.d/')]
    for path in files_to_check:
        content = _read_icat(image_path, offset, index[path])
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            m = re.match(r'^(%?\S+)\s+ALL\s*=', line)
            if m:
                entry = m.group(1)
                if entry not in sudo_entries:
                    sudo_entries.append(entry)
    return sudo_entries


def _read_group_memberships(image_path: Path, offset: int, index: dict) -> dict:
    """Liest Gruppenzugehörigkeit aus /etc/group."""
    groups: dict = {}
    if 'etc/group' not in index:
        return groups
    content = _read_icat(image_path, offset, index['etc/group'])
    for line in content.splitlines():
        parts = line.strip().split(':')
        if len(parts) < 4:
            continue
        group_name  = parts[0]
        members_str = parts[3]
        if not members_str:
            continue
        for member in members_str.split(','):
            member = member.strip()
            if member:
                groups.setdefault(member, []).append(group_name)
    return groups


def _read_installed_packages(image_path: Path, offset: int, index: dict, os_family: str) -> dict:
    """Liest installierte Pakete — Debian: dpkg/status, Alpine: apk/db/installed."""
    NOTABLE_PKGS = {
        'openssh-server', 'openssh-client', 'sudo', 'samba', 'smbclient',
        'apache2', 'nginx', 'httpd', 'docker.io', 'docker-ce', 'containerd',
        'nmap', 'netcat', 'nc', 'netcat-openbsd', 'curl', 'wget',
        'python3', 'perl', 'ruby', 'php', 'nodejs',
        'mysql-server', 'postgresql', 'mongodb', 'redis-server',
        'ufw', 'iptables', 'fail2ban', 'auditd', 'rkhunter', 'chkrootkit',
    }
    result = {'count': 0, 'notable': [], 'source': ''}

    # Debian/Ubuntu: /var/lib/dpkg/status
    if os_family in ('debian',) and 'var/lib/dpkg/status' in index:
        content = _read_icat(image_path, offset, index['var/lib/dpkg/status'])
        packages = re.findall(
            r'^Package: (.+)$.*?^Status: install ok installed',
            content, re.MULTILINE | re.DOTALL
        )
        result['count']  = len(packages)
        result['source'] = 'dpkg/status'
        result['notable'] = [p for p in packages if p.lower() in NOTABLE_PKGS]

    # Alpine: /lib/apk/db/installed
    elif os_family == 'alpine':
        for apk_path in ('lib/apk/db/installed', 'var/lib/apk/installed'):
            if apk_path not in index:
                continue
            content = _read_icat(image_path, offset, index[apk_path])
            packages = re.findall(r'^P:(.+)$', content, re.MULTILINE)
            result['count']  = len(packages)
            result['source'] = 'apk/db/installed'
            result['notable'] = [p for p in packages if p.lower() in NOTABLE_PKGS]
            break

    return result


def _read_enabled_services(index: dict, os_family: str = '') -> dict:
    """Erkennt aktivierte Services aus dem Partition-Index.

    systemd (Debian, RHEL, Arch):
      Aktiviert = in *.wants/-Verzeichnissen verlinkte .service-Dateien.

    OpenRC (Alpine):
      Aktiviert = Einträge in etc/runlevels/default/ und etc/runlevels/boot/
      (Symlinks auf /etc/init.d/<service>).

    Vergleicht aktivierte Services gegen OS-spezifische Whitelist und
    markiert unbekannte Services als 'non_standard' (forensisch relevant)."""
    enabled   = set()
    available = set()

    if os_family == 'alpine':
        # ── OpenRC (Alpine) ──────────────────────────────────────────────────
        # Aktivierte Services: Symlinks in runlevels/default/ und runlevels/boot/
        for path in index:
            if (path.startswith('etc/runlevels/default/') or
                    path.startswith('etc/runlevels/boot/')):
                svc = path.split('/')[-1]
                if svc:
                    enabled.add(svc)
            # Alle vorhandenen Init-Scripts
            elif path.startswith('etc/init.d/'):
                svc = path.split('/')[-1]
                if svc and not svc.startswith('.'):
                    available.add(svc)
    else:
        # ── systemd (Debian, RHEL, Arch) ─────────────────────────────────────
        for path in index:
            # Aktivierte Services: in *.wants/ Verzeichnissen
            if '.wants/' in path and path.endswith('.service'):
                svc = path.split('/')[-1].replace('.service', '')
                enabled.add(svc)
            # Alle vorhandenen Services
            elif (path.startswith('lib/systemd/system/') or
                  path.startswith('usr/lib/systemd/system/')) and path.endswith('.service'):
                svc = path.split('/')[-1].replace('.service', '')
                available.add(svc)

    # Nicht-Standard-Services: aktiviert, aber NICHT in OS-Whitelist
    whitelist    = STANDARD_SERVICES.get(os_family, set())
    non_standard = sorted(svc for svc in enabled if svc not in whitelist)

    return {
        'enabled':      sorted(enabled),
        'available':    sorted(available - enabled),
        'non_standard': non_standard,
    }


def _read_ssh_config(image_path: Path, offset: int, index: dict) -> dict:
    """Liest /etc/ssh/sshd_config und extrahiert forensisch relevante Direktiven."""
    cfg = {
        'permit_root_login': '', 'password_auth': '', 'pubkey_auth': '',
        'port': '22', 'allow_users': '', 'deny_users': '', 'max_auth_tries': '',
    }
    KEY_MAP = {
        'permitrootlogin':        'permit_root_login',
        'passwordauthentication': 'password_auth',
        'pubkeyauthentication':   'pubkey_auth',
        'port':                   'port',
        'allowusers':             'allow_users',
        'denyusers':              'deny_users',
        'maxauthtries':           'max_auth_tries',
    }
    if 'etc/ssh/sshd_config' not in index:
        return cfg
    content = _read_icat(image_path, offset, index['etc/ssh/sshd_config'])
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^(\S+)\s+(.+)$', line)
        if m:
            key = m.group(1).lower()
            val = m.group(2).strip()
            if key in KEY_MAP:
                cfg[KEY_MAP[key]] = val
    return cfg


def _detect_virtualization(index: dict) -> str:
    """Erkennt Virtualisierungs-/Container-Umgebung anhand von Datei-Indikatoren."""
    VIRT_INDICATORS = {
        'VMware':     ['usr/bin/vmtoolsd', 'etc/vmware-tools', 'usr/sbin/vmtoolsd'],
        'VirtualBox': ['usr/bin/vboxclient', 'etc/vbox', 'usr/sbin/vboxadd'],
        'KVM/QEMU':   ['usr/bin/qemu-ga', 'usr/sbin/qemu-ga'],
        'Docker':     ['.dockerenv'],
        'LXC':        ['etc/lxc', '.lxc'],
        'AWS':        ['etc/cloud/cloud.cfg', 'usr/bin/aws', 'var/lib/cloud'],
        'Azure':      ['etc/waagent.conf', 'usr/sbin/waagent'],
        'GCP':        ['etc/google-cloud-ops-agent', 'usr/bin/google_osconfig_agent'],
    }
    for virt_type, indicators in VIRT_INDICATORS.items():
        if any(ind in index for ind in indicators):
            return virt_type
    return 'Bare-Metal'


def _profile_partition_tsk(image_path: Path, offset: int) -> dict:
    """Liest vollständiges OS-Profil einer Partition direkt via TSK."""
    profile = {
        'os_name': '', 'os_family': 'unknown',
        'hostname': 'unknown', 'timezone': 'UTC', 'timezone_display': 'UTC',
        'kernel_version': '', 'machine_id': '', 'install_time': '',
        'users': [], 'notable_users': [], 'unexpected_users': [],
        'sudo_users': [], 'groups_map': {}, 'packages': {},
        'services': {}, 'ssh_config': {}, 'virtualization': '',
        'os_source': '',
    }
    index = get_partition_index(image_path, offset)
    if not index:
        return profile

    # OS — Prioritaetsmodell (Review-Fix #11): os-release ->
    # Distro-Releasedateien -> issue -> Paketmanager-Heuristik,
    # Gewinner-Quelle wird in os_source dokumentiert
    _os = detect_os_from_partition(image_path, offset, index)
    if _os['os_name']:
        profile['os_name']   = _os['os_name']
        profile['os_family'] = _os['os_family'] or 'unknown'
        profile['os_source'] = _os['source']

    # Hostname
    if 'etc/hostname' in index:
        raw = _read_icat(image_path, offset, index['etc/hostname'])
        if raw:
            profile['hostname'] = raw.strip()

    # Timezone
    if 'etc/timezone' in index:
        raw = _read_icat(image_path, offset, index['etc/timezone'])
        if raw:
            profile['timezone']         = raw.strip()
            profile['timezone_display'] = _format_timezone_display(raw.strip())

    # Machine-ID (Fallback-Kette inkl. dbus — Review-Fix #10)
    for mid_path in ('etc/machine-id', 'var/lib/dbus/machine-id'):
        if mid_path in index:
            raw = _read_icat(image_path, offset, index[mid_path]).strip()
            if re.fullmatch(r'[0-9a-f]{32}', raw):
                profile['machine_id'] = raw
                break

    # Kernel (aus /boot/vmlinuz-* Dateinamen) — alle Versionen, nicht nur erste
    all_k = _read_all_kernels(index)
    if all_k:
        profile['kernel_version'] = all_k[0]   # erste = GRUB-Default
        profile['all_kernels']    = all_k

    # Users aus /etc/passwd
    if 'etc/passwd' in index:
        raw = _read_icat(image_path, offset, index['etc/passwd'])
        if raw:
            profile['users'] = _parse_users(raw, profile['os_family'])
            # User-Erstellungszeiten aus auth.log/secure anreichern
            creation_times = _read_user_creation_times(image_path, offset, index)
            for u in profile['users']:
                u['created_at'] = creation_times.get(u['name'], '')
            profile['notable_users'] = [
                u['name'] for u in profile['users']
                if not u.get('is_system', True) and u.get('login_allowed', False)
            ]
            profile['unexpected_users'] = [
                u['name'] for u in profile['users'] if u.get('is_unexpected', False)
            ]

    # /etc/shadow mtime via istat
    profile['shadow_mtime'] = ''
    if 'etc/shadow' in index:
        profile['shadow_mtime'] = _read_shadow_mtime_tsk(image_path, offset, index['etc/shadow'])

    # OS-Installationszeitpunkt
    profile['install_time'] = _read_install_time(image_path, offset, index, profile['os_family'])

    # ── Erweiterte Profiling-Features ────────────────────────────────────
    last_logins   = _read_last_logins(image_path, offset, index)
    login_methods = _read_login_methods(image_path, offset, index)
    sudo_list     = _read_sudo_rights(image_path, offset, index)
    groups_map    = _read_group_memberships(image_path, offset, index)

    profile['sudo_users']    = sudo_list
    profile['groups_map']    = groups_map
    profile['packages']      = _read_installed_packages(image_path, offset, index, profile['os_family'])
    profile['services']      = _read_enabled_services(index, profile['os_family'])
    profile['ssh_config']    = _read_ssh_config(image_path, offset, index)
    profile['virtualization']= _detect_virtualization(index)
    profile['usage_period']  = _read_usage_period(image_path, offset, index, profile['os_family'])
    profile['net_config']    = _read_network_config_structured(image_path, offset, index, profile['os_family'])

    # User-Dicts anreichern
    for u in profile['users']:
        uid_entry         = last_logins.get(u['uid'], {})
        u['last_login_time'] = uid_entry.get('time', '')
        u['last_login_host'] = uid_entry.get('host', '')
        u['login_methods']   = login_methods.get(u['name'], [])
        u['groups']          = groups_map.get(u['name'], [])
        u['has_sudo']        = (u['name'] in sudo_list or
                                any(f'%{g}' in sudo_list for g in u.get('groups', [])))
        home = u.get('home', '').lstrip('/')
        name = u['name']
        u['shell_histories'] = [
            h for h in ('bash', 'zsh', 'fish')
            if f"{home}/.{h}_history" in index or
               (name == 'root' and f"root/.{h}_history" in index)
        ]

    return profile


def _read_usage_period(image_path: Path, offset: int, index: dict, os_family: str = '') -> dict:
    """Ermittelt Nutzungszeitraum: erste + letzte bekannte Aktivität via Log-Dateien."""

    # Log-Quellen je OS-Familie (inkl. rotierte Logs für ältere Einträge)
    LOG_CANDIDATES = {
        'debian': ['var/log/syslog.1', 'var/log/syslog',
                   'var/log/auth.log.1', 'var/log/auth.log'],
        'rhel':   ['var/log/messages-*', 'var/log/messages', 'var/log/secure'],
        'alpine': ['var/log/messages', 'var/log/auth.log'],
        'arch':   ['var/log/pacman.log'],
    }
    TS_PATTERNS = [
        re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'),          # ISO
        re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),             # syslog
    ]
    candidates = LOG_CANDIDATES.get(os_family, ['var/log/syslog', 'var/log/messages'])
    # Auch wildcard-artige Muster im Index matchen (z.B. messages-20240101)
    expanded = []
    for cand in candidates:
        if '*' in cand:
            prefix = cand.replace('*', '')
            expanded += [k for k in index if k.startswith(prefix)]
        elif cand in index:
            expanded.append(cand)

    result = {'first_activity': '', 'last_activity': '', 'source': ''}
    all_first: list = []

    for log_path in expanded:
        if log_path not in index:
            continue
        # Gesamten Log-Inhalt lesen — alle Timestamps extrahieren
        # (nur erste 50 Zeilen wäre unzuverlässig: letzte Aktivität könnte
        #  in der Mitte der Datei liegen wenn danach kein Timestamp mehr kommt)
        content = _read_icat(image_path, offset, index[log_path])
        if not content:
            continue

        all_ts_in_file: list = []
        for line in content.splitlines():
            for pat in TS_PATTERNS:
                m = pat.search(line)
                if m:
                    all_ts_in_file.append(m.group(1))
                    break

        if not all_ts_in_file:
            continue

        # Erster Timestamp dieser Datei → Kandidat für erste Aktivität
        all_first.append((all_ts_in_file[0], log_path))

        # Letzter Timestamp dieser Datei → Kandidat für letzte Aktivität
        last_ts  = all_ts_in_file[-1]
        curr_cmp = result['last_activity'][:19] if result['last_activity'] else ''
        if not curr_cmp or last_ts[:19] > curr_cmp:
            result['last_activity'] = last_ts
            if not result['source']:
                result['source'] = log_path

    if all_first:
        # Minimum = frühester bekannter Log-Eintrag über alle Log-Dateien
        all_first.sort(key=lambda x: x[0])
        result['first_activity'] = all_first[0][0]
        result['source']         = all_first[0][1]

    return result


def _read_network_config_structured(image_path: Path, offset: int,
                                    index: dict, os_family: str = '') -> dict:
    """Liest strukturierte Netzwerkkonfiguration: DNS, Gateway, Interfaces, MAC."""
    net = {
        'interfaces':     [],
        'dns_servers':    [],
        'search_domains': [],
        'gateway':        '',
        'mac_hints':      [],
        'source':         '',
    }

    # ── DNS aus /etc/resolv.conf ─────────────────────────────────────────
    if 'etc/resolv.conf' in index:
        content = _read_icat(image_path, offset, index['etc/resolv.conf'])
        net['dns_servers']    = re.findall(r'^nameserver\s+([\d.:a-fA-F]+)',
                                           content, re.MULTILINE)
        search = re.findall(r'^search\s+(.+)', content, re.MULTILINE)
        if search:
            net['search_domains'] = search[0].split()

    # ── Debian / Alpine: /etc/network/interfaces ──────────────────────────
    if os_family in ('debian', 'alpine') and 'etc/network/interfaces' in index:
        content = _read_icat(image_path, offset, index['etc/network/interfaces'])
        net['interfaces'] = re.findall(r'^iface\s+(\S+)\s+inet', content, re.MULTILINE)
        gw = re.search(r'^\s+gateway\s+([\d.]+)', content, re.MULTILINE)
        if gw:
            net['gateway'] = gw.group(1)
        net['source'] = 'etc/network/interfaces'

    # ── Ubuntu / Netplan: /etc/netplan/*.yaml ────────────────────────────
    netplan_files = [k for k in index if k.startswith('etc/netplan/') and k.endswith('.yaml')]
    if netplan_files:
        for nf in netplan_files:
            content = _read_icat(image_path, offset, index[nf])
            if not content:
                continue
            # YAML-Parser versuchen, Regex-Fallback
            try:
                import yaml
                data = yaml.safe_load(content) or {}
                ethernets = (data.get('network', {}) or {}).get('ethernets', {}) or {}
                for iface, cfg in ethernets.items():
                    if iface not in net['interfaces']:
                        net['interfaces'].append(iface)
                    cfg = cfg or {}
                    gw = cfg.get('gateway4') or cfg.get('gateway6', '')
                    if gw and not net['gateway']:
                        net['gateway'] = str(gw)
            except Exception:
                # Regex-Fallback
                gw = re.search(r'gateway4:\s*([\d.]+)', content)
                if gw and not net['gateway']:
                    net['gateway'] = gw.group(1)
                ifaces = re.findall(r'^\s{4}(\w[\w-]+):\s*$', content, re.MULTILINE)
                net['interfaces'] += [i for i in ifaces if i not in net['interfaces']]
        if netplan_files:
            net['source'] = netplan_files[0]

    # ── RHEL: /etc/sysconfig/network-scripts/ifcfg-* ─────────────────────
    if os_family == 'rhel':
        ifcfg_files = [k for k in index
                       if k.startswith('etc/sysconfig/network-scripts/ifcfg-')]
        for ifcfg in ifcfg_files:
            content = _read_icat(image_path, offset, index[ifcfg])
            dev = re.search(r'^DEVICE=(.+)', content, re.MULTILINE)
            gw  = re.search(r'^GATEWAY=(.+)', content, re.MULTILINE)
            if dev:
                name = dev.group(1).strip().strip('"')
                if name not in net['interfaces']:
                    net['interfaces'].append(name)
            if gw and not net['gateway']:
                net['gateway'] = gw.group(1).strip().strip('"')
        if ifcfg_files:
            net['source'] = 'etc/sysconfig/network-scripts'

    # ── MAC-Adressen — 3 Quellen ─────────────────────────────────────────
    # Quelle 1: DHCP-Lease
    for lease_path in ('var/lib/dhcp/dhclient.leases', 'var/lib/dhcpcd/dhcpcd.leases'):
        if lease_path in index:
            content = _read_icat(image_path, offset, index[lease_path])
            macs = re.findall(r'hardware ethernet\s+([\da-fA-F:]{17})', content)
            net['mac_hints'] += [m for m in macs if m not in net['mac_hints']]

    # Quelle 2: NetworkManager Verbindungsprofile
    nm_files = [k for k in index
                if 'networkmanager/system-connections' in k and k.endswith('.nmconnection')]
    for nm in nm_files:
        content = _read_icat(image_path, offset, index[nm])
        m = re.search(r'mac-address=([\da-fA-F:]{17})', content, re.IGNORECASE)
        if m and m.group(1) not in net['mac_hints']:
            net['mac_hints'].append(m.group(1))

    # Quelle 3: udev Persistent-Net-Rules
    udev_path = 'etc/udev/rules.d/70-persistent-net.rules'
    if udev_path in index:
        content = _read_icat(image_path, offset, index[udev_path])
        macs = re.findall(r'ATTR\{address\}=="([\da-fA-F:]{17})"', content)
        net['mac_hints'] += [m for m in macs if m not in net['mac_hints']]

    return net


def _read_install_time(image_path: Path, offset: int, index: dict, os_family: str = '') -> str:
    """Schätzt OS-Installationszeitpunkt — 3 Quellen, erste erfolgreiche gewinnt."""

    # Quelle 1: Installer-Logs (zuverlässigste)
    installer_paths = {
        'debian': ['var/log/installer/syslog'],
        'rhel':   ['var/log/anaconda/syslog', 'var/log/anaconda/program.log'],
    }
    for log_path in installer_paths.get(os_family, []):
        if log_path in index:
            content = _read_icat(image_path, offset, index[log_path])
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    m = re.search(r'(\d{4}-\d{2}-\d{2}[T\s][\d:]+)', line)
                    if m:
                        return m.group(1).replace('T', ' ')
                    break

    # Quelle 2 (Alpine): APK-Paketdatenbank /var/lib/apk/db/installed
    # Enthält 't:<unix-timestamp>' pro Paket — ältester Timestamp = Installationszeitpunkt
    if os_family == 'alpine' and 'var/lib/apk/db/installed' in index:
        content = _read_icat(image_path, offset, index['var/lib/apk/db/installed'])
        if content:
            timestamps = []
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('t:') and line[2:].isdigit():
                    timestamps.append(int(line[2:]))
            if timestamps:
                oldest = min(timestamps)
                try:
                    dt = datetime.fromtimestamp(oldest, tz=timezone.utc)
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass

    # Quelle 3: istat auf /etc/machine-id (generiert beim ersten Boot)
    if 'etc/machine-id' in index:
        mtime = _read_shadow_mtime_tsk(image_path, offset, index['etc/machine-id'])
        if mtime:
            return mtime

    # Quelle 4: istat auf /etc/hostname
    if 'etc/hostname' in index:
        mtime = _read_shadow_mtime_tsk(image_path, offset, index['etc/hostname'])
        if mtime:
            return mtime

    return ''


def _read_user_creation_times(image_path: Path, offset: int, index: dict) -> dict:
    """Liest User-Erstellungszeiten aus auth.log oder secure via TSK."""
    creation_times = {}
    for log_path in ('var/log/auth.log', 'var/log/secure'):
        if log_path not in index:
            continue
        content = _read_icat(image_path, offset, index[log_path])
        if not content:
            continue
        pattern = re.compile(
            r'(\w+\s+\d+\s+[\d:]+).*?(?:new user:\s*name=(\S+)|useradd.*?user\s+(\S+))',
            re.IGNORECASE
        )
        for m in pattern.finditer(content):
            ts   = m.group(1).strip()
            name = (m.group(2) or m.group(3) or '').rstrip(',')
            if name and name not in creation_times:
                creation_times[name] = ts
        break
    return creation_times


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
        # Nur vertrauen wenn Ausgabe wie os-release-Inhalt aussieht (KEY=VALUE).
        # Einzelne Wörter wie "alpine", "linux" etc. sind zu generisch — TSK-Fallback.
        if raw and raw.lower() not in ('linux', 'unknown', '') and '=' in raw:
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


def _profile_users(image_path, os_family: str = '') -> Tuple[list, str, list, list]:
    """Liest Nutzer-Profil via target-query."""
    if image_path is None:
        return [], '', [], []
    users = []
    shadow_mtime = ''
    try:
        result = subprocess.run(
            ['target-query', '-f', 'users', str(image_path)],
            capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        users = _parse_users(raw, os_family)
    except Exception as e:
        log.debug(f'target-query users fehlgeschlagen: {e}')

    # Review-Fix: der fruehere Aufruf ['target-query','-f','stat','/etc/shadow',
    # image] war fehlerhaft — target-query interpretiert '/etc/shadow' als
    # weiteres TARGET (Disk-Image). shadow_mtime wird jetzt in run() via
    # istat auf der primaeren Partition ermittelt.

    notable     = [u['name'] for u in users
                   if not u.get('is_system', True) and u.get('login_allowed', False)]
    unexpected  = [u['name'] for u in users if u.get('is_unexpected', False)]
    return users, shadow_mtime, notable, unexpected


def _parse_users(raw: str, os_family: str = '') -> list:
    """Parst /etc/passwd oder target-query users Output."""
    known = KNOWN_SYSTEM_USERS.get(os_family, set())
    users = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('<Target') or line.startswith('#'):
            continue
        parts = line.split(':')
        if len(parts) >= 7:
            try:
                uid  = int(parts[2]) if parts[2].isdigit() else -1
                name = parts[0]
                is_system    = uid < 1000 and uid >= 0
                is_known_sys = name in known if known else is_system
                users.append({
                    'name':            name,
                    'uid':             uid,
                    'gid':             int(parts[3]) if parts[3].isdigit() else -1,
                    'home':            parts[5] if len(parts) > 5 else '',
                    'shell':           parts[6].strip() if len(parts) > 6 else '',
                    'login_allowed':   parts[6].strip() not in (
                        '/bin/false', '/usr/sbin/nologin',
                        '/sbin/nologin', '/bin/nologin', '',
                    ) if len(parts) > 6 else False,
                    'is_system':       is_system,
                    'is_known_system': is_known_sys,
                    'is_unexpected':   is_system and not is_known_sys and uid > 0,
                    'has_password':    parts[1] not in ('', 'x', '*', '!') if len(parts) > 1 else False,
                    'created_at':      '',
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


# ── Anti-Forensik-Konstanten ──────────────────────────────────────────────────

GRUB_ANTIFORENSIC_PARAMS = ['init_on_free=1', 'page_poison=1', 'slub_debug=P']

KERNEL_ANTIFORENSIC_FLAGS = [
    'CONFIG_INIT_ON_FREE_DEFAULT_ON=y',
    'CONFIG_PAGE_POISONING=y',
    'CONFIG_SLUB_DEBUG=y',
]


# ── Anti-Forensik-Extraktionsfunktionen ──────────────────────────────────────

def _index_symlinks(image_path: Path, offset: int) -> Dict[str, str]:
    """Gibt {path: symlink_target} fuer alle Symlinks zurueck (fls Typ 'l/l').
    Liest Symlink-Ziel via icat — forensisch relevant fuer /dev/null Erkennung."""
    fls_cmd  = shutil.which('fls')  or 'fls'
    icat_cmd = shutil.which('icat') or 'icat'
    symlinks: Dict[str, str] = {}
    try:
        res = subprocess.run(
            [fls_cmd, '-r', '-p', '-o', str(offset), str(image_path)],
            capture_output=True, text=True, timeout=600, errors='replace'
        )
        for line in res.stdout.splitlines():
            if not line.startswith('l/l') or '\t' not in line:
                continue
            meta, path = line.split('\t', 1)
            inode  = meta.strip().split()[-1].rstrip(':')
            path_n = path.strip().removeprefix('./').lower()
            try:
                res2 = subprocess.run(
                    [icat_cmd, '-o', str(offset), str(image_path), inode],
                    capture_output=True, text=True, timeout=10, errors='replace'
                )
                if res2.returncode == 0:
                    symlinks[path_n] = res2.stdout.strip()
            except Exception:
                pass
    except Exception as e:
        log.debug(f'_index_symlinks fehlgeschlagen (offset={offset}): {e}')
    return symlinks


def _read_all_kernels(index: dict) -> List[str]:
    """Alle installierten Kernel-Versionen aus boot/vmlinuz-* Eintraegen.
    Gibt alle zurueck, nicht nur den ersten — wichtig fuer Multi-Kernel-Systeme."""
    kernels: List[str] = []
    for path in sorted(index.keys()):
        if path.startswith('boot/vmlinuz-'):
            ver = path.replace('boot/vmlinuz-', '').strip()
            if ver and ver not in kernels:
                kernels.append(ver)
    return kernels


def _read_grub_config(image_path: Path, offset: int, index: dict) -> dict:
    """Liest GRUB-Konfiguration: aktiver Kernel, Fallback-Kernel, Boot-Parameter.
    Multi-OS: boot/grub/ (Debian/Arch), boot/grub2/ (RHEL), extlinux.conf (Alpine).
    Erkennt Anti-Forensik-Parameter: init_on_free=1, page_poison=1, slub_debug=P."""
    result: dict = {
        'active_kernel':       '',
        'fallback_kernels':    [],
        'grubenv_entry':       '',
        'boot_params':         '',
        'grub_default':        '',
        'antiforensic_params': [],
        'sources':             [],
    }

    # 1. grubenv → saved_entry (Debian/Arch: grub/, RHEL: grub2/)
    for genv in ('boot/grub/grubenv', 'boot/grub2/grubenv'):
        if genv in index:
            content = _read_icat(image_path, offset, index[genv])
            m = re.search(r'^saved_entry=(.+)$', content, re.MULTILINE)
            if m:
                result['grubenv_entry'] = m.group(1).strip()
                result['sources'].append(genv)
            break

    # 2. grub.cfg → alle Kernel + set default + Anti-Forensik-Parameter
    for gcfg in ('boot/grub/grub.cfg', 'boot/grub2/grub.cfg'):
        if gcfg not in index:
            continue
        content = _read_icat(image_path, offset, index[gcfg])
        result['sources'].append(gcfg)
        m = re.search(r'^set default="?([^"\n]+)"?', content, re.MULTILINE)
        if m:
            result['grub_default'] = m.group(1).strip()
        kernels = list(dict.fromkeys(
            re.findall(r'linux\s+(?:/boot)?/vmlinuz-([a-zA-Z0-9\-\.\+]+)', content)
        ))
        if kernels:
            result['active_kernel']    = kernels[0]
            result['fallback_kernels'] = kernels[1:]
        for line in content.splitlines():
            if line.strip().startswith('linux '):
                for param in GRUB_ANTIFORENSIC_PARAMS:
                    if param in line and param not in result['antiforensic_params']:
                        result['antiforensic_params'].append(param)
        break

    # 3. /etc/default/grub → GRUB_CMDLINE_LINUX_DEFAULT (alle Distros ausser Alpine)
    if 'etc/default/grub' in index:
        content = _read_icat(image_path, offset, index['etc/default/grub'])
        result['sources'].append('etc/default/grub')
        m = re.search(r'^GRUB_CMDLINE_LINUX_DEFAULT="([^"]*)"', content, re.MULTILINE)
        if m:
            result['boot_params'] = m.group(1)
            for param in GRUB_ANTIFORENSIC_PARAMS:
                if param in result['boot_params'] and param not in result['antiforensic_params']:
                    result['antiforensic_params'].append(param)
        m2 = re.search(r'^GRUB_DEFAULT=(.+)$', content, re.MULTILINE)
        if m2 and not result['grub_default']:
            result['grub_default'] = m2.group(1).strip().strip('"')

    # 4. Alpine Fallback: Syslinux extlinux.conf
    if not result['active_kernel'] and 'boot/extlinux.conf' in index:
        content = _read_icat(image_path, offset, index['boot/extlinux.conf'])
        result['sources'].append('boot/extlinux.conf')
        m = re.search(r'KERNEL\s+/boot/vmlinuz-([a-zA-Z0-9\-\.\+]+)', content)
        if m:
            result['active_kernel'] = m.group(1)
        for param in GRUB_ANTIFORENSIC_PARAMS:
            if param in content and param not in result['antiforensic_params']:
                result['antiforensic_params'].append(param)

    return result


def _read_kernel_compile_flags(image_path: Path, offset: int,
                                index: dict, kernels: List[str]) -> dict:
    """Liest /boot/config-<kernel> fuer alle Kernel-Versionen.
    Gleich fuer alle Distros — Pfad und Flag-Namen sind kernel-level Standard.
    Erkennt: CONFIG_INIT_ON_FREE_DEFAULT_ON, CONFIG_PAGE_POISONING, CONFIG_SLUB_DEBUG."""
    result: dict = {}
    for kernel in kernels:
        cfg_path = f'boot/config-{kernel}'
        if cfg_path not in index:
            continue
        content = _read_icat(image_path, offset, index[cfg_path])
        if not content:
            continue
        active = [f for f in KERNEL_ANTIFORENSIC_FLAGS if f in content]
        result[kernel] = {
            'active_flags':      active,
            'has_antiforensics': bool(active),
        }
    return result


def _read_swap_config(image_path: Path, offset: int, index: dict) -> dict:
    """Parst /etc/fstab auf Swap-Eintraege (Partition, Datei, UUID).
    Gleich fuer alle Distros — fstab ist POSIX-Standard."""
    result: dict = {'found': False, 'entries': []}
    if 'etc/fstab' not in index:
        return result
    content = _read_icat(image_path, offset, index['etc/fstab'])
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[2] == 'swap':
            result['found'] = True
            target = parts[0]
            swap_type = (
                'partition'      if target.startswith('/dev/')
                else 'partition_uuid' if target.startswith(('UUID=', 'PARTUUID='))
                else 'file'
            )
            result['entries'].append({'type': swap_type, 'path': target, 'size_mb': 0.0})
    return result


def _read_rc_local(image_path: Path, offset: int,
                   index: dict, os_family: str = '') -> str:
    """Liest /etc/rc.local Inhalt (Startup-Script).
    Multi-OS: Debian/RHEL/Arch = etc/rc.local, Alpine = etc/local.d/*.start."""
    for rc_path in ('etc/rc.local', 'etc/rc.d/rc.local'):
        if rc_path in index:
            return _read_icat(image_path, offset, index[rc_path])
    if os_family == 'alpine':
        parts = []
        for path in sorted(index):
            if path.startswith('etc/local.d/') and path.endswith('.start'):
                parts.append(_read_icat(image_path, offset, index[path]))
        if parts:
            return '\n'.join(parts)
    return ''


def _check_reboot_pending(index: dict, os_family: str = '') -> bool:
    """Prueft ob ein ausstehender Neustart vorliegt.
    Debian: var/run/reboot-required Flag (zuverlässig).
    RHEL/Arch/Alpine: kein standardisiertes Flag im Image erkennbar."""
    return any(p in index for p in ('var/run/reboot-required', 'run/reboot-required'))


def _read_loaded_kernel_from_logs(image_path: Path, offset: int,
                                   index: dict, os_family: str) -> str:
    """Liest tatsaechlich geladenen Kernel aus Kernel-Logs.

    Strategie (Reihenfolge):
    1. Text-Logs (kern.log / messages / syslog) via icat → direkt lesbar
    2. Systemd Journal-Dateien (*.journal) via journalctl --file →
       korrekte Handhabung von LZ4-komprimierten Binärdateien (systemd v230+).
       Nur diese Option wird verwendet — kein Binary-String-Fallback,
       da LZ4-Kompression Strings unzuverlässig macht.

    Multi-OS: Debian/Arch = kern.log, RHEL/Alpine = messages.
    Suchbegriff 'Linux version X.Y.Z' ist kernel-level — überall gleich."""
    LOG_CANDIDATES: Dict[str, List[str]] = {
        'debian': ['var/log/kern.log', 'var/log/syslog'],
        'rhel':   ['var/log/messages'],
        'alpine': ['var/log/messages', 'var/log/syslog'],
        'arch':   ['var/log/kern.log', 'var/log/syslog'],
    }
    pattern = re.compile(r'Linux version ([a-zA-Z0-9\-\.\+]+)')
    icat_cmd = shutil.which('icat') or 'icat'

    # ── Schritt 1: Text-Logs ──────────────────────────────────────────────
    for log_path in LOG_CANDIDATES.get(os_family, ['var/log/kern.log', 'var/log/messages']):
        if log_path not in index:
            continue
        content = _read_icat(image_path, offset, index[log_path])
        for line in content.splitlines():
            if 'Linux version' in line:
                m = pattern.search(line)
                if m:
                    log.debug(f'  Kernel aus Text-Log gefunden ({log_path}): {m.group(1)}')
                    return m.group(1)

    # ── Schritt 2: Systemd Journal via journalctl --file ─────────────────
    # Nur wenn journalctl verfügbar ist (systemd-Systeme: Debian, RHEL, Arch)
    if shutil.which('journalctl') and os_family != 'alpine':
        journal_entries = sorted(
            [(path, inode) for path, inode in index.items()
             if path.startswith('var/log/journal/') and path.endswith('.journal')]
        )
        if journal_entries:
            log.debug(f'  Prüfe {len(journal_entries)} Journal-Datei(en) via journalctl --file')
        for j_path, j_inode in journal_entries[:3]:   # max. 3 Dateien prüfen
            tmp_path: str = ''
            try:
                # Journal-Datei aus Image extrahieren
                with tempfile.NamedTemporaryFile(suffix='.journal', delete=False) as tf:
                    tmp_path = tf.name
                res_icat = subprocess.run(
                    [icat_cmd, '-o', str(offset), str(image_path), j_inode],
                    capture_output=True, timeout=30
                )
                if res_icat.returncode != 0 or not res_icat.stdout:
                    log.debug(f'  icat fehlgeschlagen für {j_path}')
                    continue
                with open(tmp_path, 'wb') as f:
                    f.write(res_icat.stdout)
                # journalctl --file liest LZ4-komprimierte Journals transparent
                res_jctl = subprocess.run(
                    ['journalctl', '--file', tmp_path,
                     '-k', '--no-pager', '--output=short'],
                    capture_output=True, text=True, timeout=30, errors='replace'
                )
                for line in res_jctl.stdout.splitlines():
                    if 'Linux version' in line:
                        m = pattern.search(line)
                        if m:
                            log.debug(f'  Kernel aus Journal gefunden ({j_path}): {m.group(1)}')
                            return m.group(1)
            except Exception as e:
                log.debug(f'  journalctl --file fehlgeschlagen ({j_path}): {e}')
            finally:
                if tmp_path:
                    try:
                        Path(tmp_path).unlink(missing_ok=True)
                    except Exception:
                        pass

    return ''
