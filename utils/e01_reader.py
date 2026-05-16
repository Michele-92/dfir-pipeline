import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def read_e01_hashes(path: Path) -> tuple[str, str]:
    """Liest eingebettete MD5 + SHA1 aus E01-Datei via ewfinfo.

    E01 (EnCase Expert Witness Format) speichert Hashes intern —
    diese wurden beim Imaging erstellt und sind Teil der originalen
    Beweissicherung. Returns (md5, sha1). Leere Strings bei Fehler.
    Benötigt: sudo apt install ewf-tools
    """
    try:
        result = subprocess.run(
            ['ewfinfo', str(path)],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr

        md5  = _extract_hash(output, 'MD5')
        sha1 = _extract_hash(output, 'SHA1')

        if md5 or sha1:
            log.info(f'  E01-Hash gelesen: MD5={md5[:8]}...  SHA1={sha1[:8] if sha1 else "—"}')
        return md5, sha1

    except FileNotFoundError:
        log.debug('ewfinfo nicht installiert (sudo apt install ewf-tools) — Hash wird berechnet')
        return '', ''
    except subprocess.TimeoutExpired:
        log.debug('ewfinfo Timeout — Hash wird berechnet')
        return '', ''
    except Exception as e:
        log.debug(f'E01-Hash-Auslesen fehlgeschlagen: {e}')
        return '', ''


def _extract_hash(text: str, hash_type: str) -> str:
    """Extrahiert Hash-Wert aus ewfinfo Output."""
    pattern = rf'{hash_type}\s*:\s*([0-9a-fA-F]{{32,64}})'
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return ''
