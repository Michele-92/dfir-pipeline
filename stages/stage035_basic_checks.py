import logging
from models.pipeline_context import PipelineContext

log = logging.getLogger(__name__)

# Erwartete Services/Logs pro Distribution
EXPECTED_SERVICES = {
    'debian': {
        'mandatory': {
            'syslog':  '/var/log/syslog',
            'auth':    '/var/log/auth.log',
            'kern':    '/var/log/kern.log',
        },
        'if_installed': {
            'samba':      ['/var/log/samba/log.smbd', '/var/log/samba/log.nmbd'],
            'apache2':    ['/var/log/apache2/access.log', '/var/log/apache2/error.log'],
            'nginx':      ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
            'mysql':      ['/var/log/mysql/error.log'],
            'postgresql': ['/var/log/postgresql/'],
            'auditd':     ['/var/log/audit/audit.log'],
            'fail2ban':   ['/var/log/fail2ban.log'],
            'ufw':        ['/var/log/ufw.log'],
            'docker':     ['/var/log/docker.log'],
        }
    },
    'rhel': {
        'mandatory': {
            'messages': '/var/log/messages',
            'secure':   '/var/log/secure',
        },
        'if_installed': {
            'httpd':      ['/var/log/httpd/access_log', '/var/log/httpd/error_log'],
            'samba':      ['/var/log/samba/log.smbd'],
            'auditd':     ['/var/log/audit/audit.log'],
            'mysql':      ['/var/log/mysqld.log'],
            'postgresql': ['/var/log/postgresql/'],
            'docker':     ['/var/log/docker'],
        }
    },
    'arch': {
        'mandatory': {
            'pacman': '/var/log/pacman.log',
        },
        'if_installed': {
            'samba':  ['/var/log/samba/'],
            'apache': ['/var/log/httpd/'],
            'nginx':  ['/var/log/nginx/'],
        }
    },
    'alpine': {
        'mandatory': {
            'messages': '/var/log/messages',
            'auth':     '/var/log/auth.log',
        },
        'if_installed': {
            'nginx':      ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
            'apache2':    ['/var/log/apache2/access.log', '/var/log/apache2/error.log'],
            'mysql':      ['/var/log/mysql/error.log'],
            'docker':     ['/var/log/docker.log'],
            'samba':      ['/var/log/samba/log.smbd'],
        }
    },
}


def run(ctx: PipelineContext) -> PipelineContext:
    log.info('Stage 3.5: Basic Checks')
    profile = EXPECTED_SERVICES.get(ctx.os_family)
    if not profile:
        log.info(f'  Kein Profil für OS-Familie "{ctx.os_family}" — Basic Checks übersprungen')
        ctx.stage_status['stage_03_5'] = f'ÜBERSPRUNGEN — kein Profil für {ctx.os_family}'
        return ctx

    extracted = set(ctx.tsk_extracted_filenames)
    checks    = []

    # 1. Pflicht-Logs prüfen
    for service, log_path in profile.get('mandatory', {}).items():
        found  = _is_present(log_path, extracted)
        status = 'OK' if found else 'FEHLT ⚠️'
        anomaly = '' if found else f'Pflicht-Log fehlt: {log_path}'
        checks.append({
            'service':     service,
            'log_path':    log_path,
            'expected':    True,
            'found':       found,
            'status':      status,
            'anomaly':     anomaly,
            'anomaly_type':'mandatory_missing' if not found else '',
        })
        log.info(f'  [{status}] {service}: {log_path}')

    # 2. Installierte Pakete ermitteln → erwartete Logs prüfen
    installed = _get_installed_packages(ctx)
    for pkg, log_paths in profile.get('if_installed', {}).items():
        if pkg not in installed:
            # Paket nicht installiert → prüfe ob trotzdem Logs vorhanden
            for lp in log_paths:
                if _is_present(lp, extracted):
                    checks.append({
                        'service':     pkg,
                        'log_path':    lp,
                        'expected':    False,
                        'found':       True,
                        'status':      'LOG OHNE INSTALLATION ⚠️',
                        'anomaly':     f'{lp} vorhanden, aber {pkg} nicht installiert',
                        'anomaly_type':'log_without_install',
                    })
                    log.info(f'  [LOG OHNE INSTALL ⚠️] {pkg}: {lp}')
                else:
                    checks.append({
                        'service':     pkg,
                        'log_path':    lp,
                        'expected':    False,
                        'found':       False,
                        'status':      'nicht installiert',
                        'anomaly':     '',
                        'anomaly_type':'',
                    })
        else:
            # Paket installiert → prüfe ob Logs vorhanden
            for lp in log_paths:
                found = _is_present(lp, extracted)
                if not found:
                    checks.append({
                        'service':     pkg,
                        'log_path':    lp,
                        'expected':    True,
                        'found':       False,
                        'status':      'INSTALLIERT ABER KEIN LOG ⚠️',
                        'anomaly':     f'{pkg} installiert, aber {lp} fehlt',
                        'anomaly_type':'install_without_log',
                    })
                    log.info(f'  [KEIN LOG ⚠️] {pkg} installiert aber {lp} fehlt')
                else:
                    checks.append({
                        'service':     pkg,
                        'log_path':    lp,
                        'expected':    True,
                        'found':       True,
                        'status':      'OK',
                        'anomaly':     '',
                        'anomaly_type':'',
                    })

    ctx.basic_checks          = checks
    ctx.basic_check_anomalies = sum(1 for c in checks if c['anomaly'])

    log.info(f'  Basic Checks: {len(checks)} geprüft, {ctx.basic_check_anomalies} Anomalien')
    if ctx.coc:
        ctx.coc.add_entry('stage_03_5', f'Basic Checks: {ctx.basic_check_anomalies} Anomalien')
    return ctx


def _is_present(log_path: str, extracted: set) -> bool:
    """Prüft ob ein Log-Pfad in den extrahierten Dateien vorkommt."""
    log_path_lower = log_path.lower()
    return any(log_path_lower in f.lower() for f in extracted)


def _get_installed_packages(ctx: PipelineContext) -> set:
    """Ermittelt installierte Pakete aus dpkg/rpm Log-Artefakten."""
    installed = set()
    # Debian: aus dpkg.log oder apt/history.log
    for event in ctx.normalized_events:
        msg = event.message.lower()
        if event.source in ('dpkg', 'apt_history'):
            # "install <paketname>:" Pattern
            if 'install ' in msg:
                parts = msg.split('install ')
                if len(parts) > 1:
                    pkg = parts[1].split(':')[0].split(' ')[0].strip()
                    if pkg:
                        installed.add(pkg)
    # Bekannte häufige Pakete aus tsk_extracted_filenames ableiten
    for fname in ctx.tsk_extracted_filenames:
        fname_lower = fname.lower()
        if 'apache2' in fname_lower: installed.add('apache2')
        if 'nginx'   in fname_lower: installed.add('nginx')
        if 'mysql'   in fname_lower: installed.add('mysql')
        if 'samba'   in fname_lower: installed.add('samba')
        if 'docker'  in fname_lower: installed.add('docker')
        if 'postgres' in fname_lower: installed.add('postgresql')
        if 'fail2ban' in fname_lower: installed.add('fail2ban')
        if 'auditd'  in fname_lower or 'audit.log' in fname_lower: installed.add('auditd')
    return installed
