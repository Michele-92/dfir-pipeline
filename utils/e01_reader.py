import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_TSK_PREFIX = '/usr/local/bin/'

def _tsk(cmd: str) -> str:
    local = Path(f'{_TSK_PREFIX}{cmd}')
    return str(local) if local.exists() else cmd


def read_e01_hashes(path: Path) -> tuple[str, str]:
    """Liest eingebettete MD5 aus E01-Datei via TSK img_stat.

    E01 (EnCase Expert Witness Format) speichert den MD5-Hash intern —
    dieser wurde beim Imaging erstellt und ist Teil der originalen
    Beweissicherung. img_stat ist Teil von TSK und bereits installiert.
    Returns (md5, sha1). Leere Strings bei Fehler.
    """
    try:
        result = subprocess.run(
            [_tsk('img_stat'), str(path)],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr

        md5  = _extract_hash(output, 'MD5')
        sha1 = _extract_hash(output, 'SHA1')

        if md5 or sha1:
            log.info(f'  E01-Hash gelesen (img_stat): MD5={md5[:8]}...  SHA1={sha1[:8] if sha1 else "—"}')
        return md5, sha1

    except FileNotFoundError:
        log.debug('img_stat nicht gefunden — Hash wird berechnet')
        return '', ''
    except subprocess.TimeoutExpired:
        log.debug('img_stat Timeout — Hash wird berechnet')
        return '', ''
    except Exception as e:
        log.debug(f'E01-Hash-Auslesen fehlgeschlagen: {e}')
        return '', ''


def _extract_hash(text: str, hash_type: str) -> str:
    """Extrahiert Hash-Wert aus img_stat Output."""
    pattern = rf'{hash_type}\s*:\s*([0-9a-fA-F]{{32,64}})'
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return ''
