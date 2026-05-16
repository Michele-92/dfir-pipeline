import logging
from pathlib import Path

log = logging.getLogger(__name__)


def read_e01_hashes(path: Path) -> tuple[str, str]:
    """Liest eingebettete MD5 + SHA1 aus E01-Datei-Header.

    E01 (EnCase Expert Witness Format) speichert Hashes intern —
    diese wurden beim Imaging erstellt und sind Teil der originalen
    Beweissicherung. Returns (md5, sha1). Leere Strings bei Fehler.
    """
    try:
        import pyewf
        filenames = [str(path)]
        # Prüfe ob .E01 Segmente existieren (.E02, .E03 usw.)
        for i in range(2, 100):
            segment = path.with_suffix(f'.E{i:02d}')
            if segment.exists():
                filenames.append(str(segment))
            else:
                break
        handle = pyewf.handle()
        handle.open(filenames)
        md5  = handle.get_hash_value('MD5')  or ''
        sha1 = handle.get_hash_value('SHA1') or ''
        handle.close()
        log.info(f'  E01-Hash gelesen: MD5={md5[:8]}...  SHA1={sha1[:8]}...')
        return md5, sha1
    except ImportError:
        log.debug('pyewf nicht installiert — Hash wird berechnet')
        return '', ''
    except Exception as e:
        log.debug(f'E01-Hash-Auslesen fehlgeschlagen: {e}')
        return '', ''
